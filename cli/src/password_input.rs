//! Bounded, cancellable hidden terminal input for a live recovery exchange.
use anyhow::{bail, Context, Result};
use rustix::event::{poll, PollFd, PollFlags, Timespec};
use rustix::termios::{tcflush, tcgetattr, tcsetattr, OptionalActions, QueueSelector, Termios};
use std::fs::File;
use std::io::Write;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::Instant;
use tokio::sync::Semaphore;
use zeroize::Zeroizing;

static TERMINAL_READER: Semaphore = Semaphore::const_new(1);

struct TerminalMode<'a> {
    file: &'a File,
    original: Termios,
}
impl Drop for TerminalMode<'_> {
    fn drop(&mut self) {
        let _ = tcflush(self.file, QueueSelector::IFlush);
        let _ = tcsetattr(self.file, OptionalActions::Now, &self.original);
    }
}
struct CancelOnDrop(Arc<AtomicBool>);
impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

fn hidden_line(
    tty: &mut File,
    prompt: &str,
    limit: usize,
    deadline: Instant,
    cancelled: &AtomicBool,
) -> Result<Zeroizing<String>> {
    tty.write_all(prompt.as_bytes())?;
    tty.flush()?;
    let mut bytes = Zeroizing::new(Vec::new());
    loop {
        if cancelled.load(Ordering::Acquire) || Instant::now() >= deadline {
            bail!("recovery input cancelled or expired");
        }
        let mut events = [PollFd::new(tty, PollFlags::IN)];
        if poll(
            &mut events,
            Some(&Timespec {
                tv_sec: 0,
                tv_nsec: 100_000_000,
            }),
        )? == 0
        {
            continue;
        }
        let mut byte = Zeroizing::new([0u8; 1]);
        match rustix::io::read(&*tty, &mut *byte) {
            Ok(0) => bail!("terminal closed"),
            Ok(_) => {}
            Err(rustix::io::Errno::AGAIN) => continue,
            Err(error) => return Err(error.into()),
        }
        match byte[0] {
            b'\r' | b'\n' => {
                tty.write_all(b"\r\n")?;
                break;
            }
            3 | 4 => bail!("recovery input cancelled"),
            8 | 127 => {
                if let Some(last) = bytes.last().copied() {
                    *bytes.last_mut().expect("nonempty buffer") = 0;
                    bytes.pop();
                    if last & 0xc0 == 0x80 {
                        while bytes.last().is_some_and(|b| b & 0xc0 == 0x80) {
                            *bytes.last_mut().expect("nonempty buffer") = 0;
                            bytes.pop();
                        }
                        if let Some(last) = bytes.last_mut() {
                            *last = 0;
                            bytes.pop();
                        }
                    }
                }
            }
            byte => {
                if bytes.len() >= limit {
                    bail!("hidden input exceeds {limit} bytes");
                }
                bytes.push(byte);
            }
        }
    }
    // Convert without an intermediate, non-zeroizing secret allocation.
    std::str::from_utf8(&bytes).context("hidden input is not UTF-8")?;
    Ok(Zeroizing::new(
        String::from_utf8(std::mem::take(&mut *bytes)).expect("validated UTF-8"),
    ))
}

pub async fn recovery_credentials(
    conn: &iroh::endpoint::Connection,
    deadline: Instant,
) -> Result<(Zeroizing<String>, Zeroizing<String>, Zeroizing<String>)> {
    let permit = TERMINAL_READER
        .try_acquire()
        .context("another terminal prompt is still active")?;
    let cancelled = Arc::new(AtomicBool::new(false));
    let cancel_guard = CancelOnDrop(cancelled.clone());
    let worker_cancel = cancelled.clone();
    let mut worker = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let fd = rustix::fs::open(
            "/dev/tty",
            rustix::fs::OFlags::RDWR | rustix::fs::OFlags::NONBLOCK | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )?;
        let mut tty: File = fd.into();
        let original = tcgetattr(&tty)?;
        let mut raw = original.clone();
        raw.make_raw();
        let restore_file = tty.try_clone()?;
        tcsetattr(&tty, OptionalActions::Now, &raw)?;
        let _mode = TerminalMode {
            file: &restore_file,
            original,
        };
        let password = hidden_line(
            &mut tty,
            "recovery-file master password: ",
            ferusa_core::recovery::MAX_RECOVERY_PASSWORD_BYTES,
            deadline,
            &worker_cancel,
        )?;
        let pin4 = hidden_line(
            &mut tty,
            "phone PIN 1 (4 digits): ",
            4,
            deadline,
            &worker_cancel,
        )?;
        let pin6 = hidden_line(
            &mut tty,
            "phone PIN 2 (6 digits): ",
            6,
            deadline,
            &worker_cancel,
        )?;
        Ok::<_, anyhow::Error>((password, pin4, pin6))
    });
    tokio::select! {
        result = &mut worker => { drop(cancel_guard); result.context("terminal worker failed")? },
        _ = conn.closed() => { cancelled.store(true, Ordering::Release); let _ = worker.await; bail!("phone disconnected during recovery input"); },
        _ = tokio::time::sleep_until(deadline.into()) => { cancelled.store(true, Ordering::Release); let _ = worker.await; bail!("recovery request expired during terminal input"); },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use std::os::{fd::OwnedFd, unix::net::UnixStream};
    use std::time::Duration;

    fn read_input(input: &[u8], limit: usize) -> Result<Zeroizing<String>> {
        let (reader, mut writer) = UnixStream::pair().unwrap();
        reader.set_nonblocking(true).unwrap();
        let owned: OwnedFd = reader.into();
        let mut file = File::from(owned);
        let task = std::thread::spawn(move || {
            hidden_line(
                &mut file,
                "input: ",
                limit,
                Instant::now() + Duration::from_secs(2),
                &AtomicBool::new(false),
            )
        });
        let mut prompt = [0; 7];
        writer.read_exact(&mut prompt).unwrap();
        writer.write_all(input).unwrap();
        task.join().unwrap()
    }
    #[test]
    fn hidden_input_preserves_whitespace_unicode_and_leading_zero_pins() {
        assert_eq!(
            read_input("  päss word  \n".as_bytes(), 100)
                .unwrap()
                .as_str(),
            "  päss word  "
        );
        assert_eq!(read_input(b"0012\n", 4).unwrap().as_str(), "0012");
        assert_eq!(
            read_input("aé\u{7f}b\n".as_bytes(), 100).unwrap().as_str(),
            "ab"
        );
        assert!(read_input(b"12345\n", 4).is_err());
        assert!(read_input(b"secret\x03", 100).is_err());
    }
    #[test]
    fn pending_terminal_input_expires_and_cancellation_is_bounded() {
        for cancelled in [false, true] {
            let (reader, _writer) = UnixStream::pair().unwrap();
            reader.set_nonblocking(true).unwrap();
            let owned: OwnedFd = reader.into();
            let mut file = File::from(owned);
            let start = Instant::now();
            assert!(hidden_line(
                &mut file,
                "",
                100,
                start + Duration::from_millis(20),
                &AtomicBool::new(cancelled)
            )
            .is_err());
            assert!(start.elapsed() < Duration::from_secs(1));
        }
    }
}

//! Fixed-capacity PCM ingress queue. Overflow fails closed and records an integrity flag.

use std::sync::{\n    Mutex,\n    atomic::{AtomicBool, Ordering},\n};\nuse zeroize::Zeroize;

const MAX_QUEUE_BLOCKS: u32 = 256;
const MAX_BLOCK_BYTES: u32 = 256 * 1024;
const MAX_TOTAL_QUEUE_BYTES: usize = 8 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CaptureStatus {
    Running,
    Stopping,
    Stopped,
    Failed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CaptureError {
    InvalidConfiguration,
    InvalidBlock,
    InvalidState,
    QueueOverflow,
    ResourcePoisoned,
    QueueContention,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PcmMetadata {
    pub sample_rate_hz: u32,
    pub channels: u16,
    pub sample_format: u16,
    pub frames: u32,
    pub first_frame_index: u64,
    pub monotonic_timestamp_ns: u64,
    pub capture_epoch: u64,
    pub sequence: u32,
}

struct Slot {
    bytes: Box<[u8]>,
    len: usize,
    metadata: Option<PcmMetadata>,
}

impl Drop for Slot {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

struct Inner {
    slots: Vec<Slot>,
    head: usize,
    tail: usize,
    queued: usize,
    status: CaptureStatus,
    integrity_overflow: bool,
}

/// Allocates fixed payload slots at construction; submit never grows the queue.
pub struct BoundedPcmQueue {
    capacity: usize,
    max_bytes: usize,
    inner: Mutex<Inner>,
    producer_fault: AtomicBool,
}

impl BoundedPcmQueue {
    pub fn new(capacity: u32, max_block_frames: u32) -> Result<Self, CaptureError> {
        let block_bytes = max_block_frames
            .checked_mul(2)
            .filter(|bytes| *bytes <= MAX_BLOCK_BYTES)
            .ok_or(CaptureError::InvalidConfiguration)?;
        if capacity == 0 || capacity > MAX_QUEUE_BLOCKS || max_block_frames == 0 {
            return Err(CaptureError::InvalidConfiguration);
        }
        let max_bytes = block_bytes as usize;
        let total_bytes = max_bytes
            .checked_mul(capacity as usize)
            .filter(|bytes| *bytes <= MAX_TOTAL_QUEUE_BYTES)
            .ok_or(CaptureError::InvalidConfiguration)?;

        let mut slots = Vec::new();
        slots
            .try_reserve_exact(capacity as usize)
            .map_err(|_| CaptureError::InvalidConfiguration)?;
        for _ in 0..capacity {
            let mut bytes = Vec::new();
            bytes
                .try_reserve_exact(max_bytes)
                .map_err(|_| CaptureError::InvalidConfiguration)?;
            bytes.resize(max_bytes, 0);
            slots.push(Slot {
                bytes: bytes.into_boxed_slice(),
                len: 0,
                metadata: None,
            });
        }

        debug_assert_eq!(total_bytes, max_bytes * capacity as usize);
        Ok(Self {
            capacity: capacity as usize,
            max_bytes,
            producer_fault: AtomicBool::new(false),
            inner: Mutex::new(Inner {
                slots,
                head: 0,
                tail: 0,
                queued: 0,
                status: CaptureStatus::Running,
                integrity_overflow: false,
            }),
        })
    }

    pub fn submit(&self, metadata: PcmMetadata, pcm: &[u8]) -> Result<(), CaptureError> {
        let expected_bytes = (metadata.frames as usize)
            .checked_mul(2)
            .ok_or(CaptureError::InvalidBlock)?;
        if (metadata.sample_rate_hz != 48_000 && metadata.sample_rate_hz != 44_100)
            || metadata.channels != 1
            || metadata.sample_format != 1
            || metadata.frames == 0
            || expected_bytes != pcm.len()
            || pcm.len() > self.max_bytes
        {
            return Err(CaptureError::InvalidBlock);
        }

        let mut inner = match self.inner.try_lock() {
            Ok(guard) => guard,
            Err(std::sync::TryLockError::WouldBlock) => {
                self.producer_fault.store(true, Ordering::Release);
                return Err(CaptureError::QueueContention);
            }
            Err(std::sync::TryLockError::Poisoned(_)) => return Err(CaptureError::ResourcePoisoned),
        };
        if self.producer_fault.load(Ordering::Acquire) {
            inner.status = CaptureStatus::Failed;
            inner.integrity_overflow = true;
            return Err(CaptureError::QueueContention);
        }
        if inner.status != CaptureStatus::Running {
            return Err(CaptureError::InvalidState);
        }
        if inner.queued == self.capacity {
            inner.status = CaptureStatus::Failed;
            inner.integrity_overflow = true;
            return Err(CaptureError::QueueOverflow);
        }

        let tail = inner.tail;
        let slot = &mut inner.slots[tail];
        slot.bytes[..pcm.len()].copy_from_slice(pcm);
        slot.len = pcm.len();
        slot.metadata = Some(metadata);
        inner.tail = (tail + 1) % self.capacity;
        inner.queued += 1;
        Ok(())
    }

    pub fn pop_into(
        &self,
        output: &mut [u8],
    ) -> Result<Option<(PcmMetadata, usize)>, CaptureError> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| CaptureError::ResourcePoisoned)?;
        if inner.queued == 0 {
            return Ok(None);
        }

        let head = inner.head;
        let slot = &mut inner.slots[head];
        if output.len() < slot.len {
            return Err(CaptureError::InvalidBlock);
        }
        output[..slot.len].copy_from_slice(&slot.bytes[..slot.len]);
        let metadata = slot.metadata.take().ok_or(CaptureError::InvalidBlock)?;
        let len = slot.len;
        slot.len = 0;
        inner.head = (head + 1) % self.capacity;
        inner.queued -= 1;
        Ok(Some((metadata, len)))
    }

    pub fn request_stop(&self) -> Result<(), CaptureError> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| CaptureError::ResourcePoisoned)?;
        if inner.status != CaptureStatus::Running {
            return Err(CaptureError::InvalidState);
        }
        inner.status = CaptureStatus::Stopping;
        Ok(())
    }

    pub fn mark_stopped(&self) -> Result<(), CaptureError> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| CaptureError::ResourcePoisoned)?;
        if inner.status != CaptureStatus::Stopping || inner.queued != 0 {
            return Err(CaptureError::InvalidState);
        }
        inner.status = CaptureStatus::Stopped;
        Ok(())
    }

    pub fn status(&self) -> Result<CaptureStatus, CaptureError> {
        if self.producer_fault.load(Ordering::Acquire) { return Ok(CaptureStatus::Failed); }
        Ok(self
            .inner
            .lock()
            .map_err(|_| CaptureError::ResourcePoisoned)?
            .status)
    }

    pub fn integrity_overflow(&self) -> Result<bool, CaptureError> {
        if self.producer_fault.load(Ordering::Acquire) { return Ok(true); }
        Ok(self
            .inner
            .lock()
            .map_err(|_| CaptureError::ResourcePoisoned)?
            .integrity_overflow)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn metadata(sequence: u32, frames: u32) -> PcmMetadata {
        PcmMetadata {
            sample_rate_hz: 48_000,
            channels: 1,
            sample_format: 1,
            frames,
            first_frame_index: sequence as u64 * frames as u64,
            monotonic_timestamp_ns: sequence as u64 + 1,
            capture_epoch: 9,
            sequence,
        }
    }

    #[test]
    fn fifo_preserves_pcm() {
        let queue = BoundedPcmQueue::new(2, 4).unwrap();
        queue.submit(metadata(0, 2), &[1, 2, 3, 4]).unwrap();
        queue.submit(metadata(1, 1), &[5, 6]).unwrap();
        let mut output = [0; 8];
        let (first, len) = queue.pop_into(&mut output).unwrap().unwrap();
        assert_eq!(first.sequence, 0);
        assert_eq!(&output[..len], &[1, 2, 3, 4]);
        let (second, len) = queue.pop_into(&mut output).unwrap().unwrap();
        assert_eq!(second.sequence, 1);
        assert_eq!(&output[..len], &[5, 6]);
    }

    #[test]
    fn overflow_fails_closed_and_records_integrity_flag() {
        let queue = BoundedPcmQueue::new(1, 2).unwrap();
        queue.submit(metadata(0, 1), &[0, 0]).unwrap();
        assert_eq!(
            queue.submit(metadata(1, 1), &[1, 1]),
            Err(CaptureError::QueueOverflow)
        );
        assert_eq!(queue.status().unwrap(), CaptureStatus::Failed);
        assert!(queue.integrity_overflow().unwrap());
        assert_eq!(
            queue.submit(metadata(2, 1), &[2, 2]),
            Err(CaptureError::InvalidState)
        );
    }

    #[test]
    fn invalid_payload_shape_is_rejected() {
        let queue = BoundedPcmQueue::new(2, 8).unwrap();
        assert_eq!(
            queue.submit(metadata(0, 2), &[1, 2]),
            Err(CaptureError::InvalidBlock)
        );
    }

    #[test]
    fn stop_requires_drain_before_terminal_state() {
        let queue = BoundedPcmQueue::new(2, 4).unwrap();
        queue.submit(metadata(0, 1), &[0, 0]).unwrap();
        queue.request_stop().unwrap();
        assert_eq!(queue.mark_stopped(), Err(CaptureError::InvalidState));
        let mut output = [0; 8];
        queue.pop_into(&mut output).unwrap();
        queue.mark_stopped().unwrap();
        assert_eq!(queue.status().unwrap(), CaptureStatus::Stopped);
    }

    #[test]
    fn rejects_queue_memory_above_budget() {
        assert!(matches!(
            BoundedPcmQueue::new(256, 131_072),
            Err(CaptureError::InvalidConfiguration)
        ));
    }
}

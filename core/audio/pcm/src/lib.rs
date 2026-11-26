//! Canonical PCM validation and zero-allocation S16LE decoding.
#![forbid(unsafe_code)]

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SampleFormat {
    Signed16LittleEndian,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PcmFormat {
    pub sample_rate_hz: u32,
    pub channels: u16,
    pub sample_format: SampleFormat,
}

impl PcmFormat {
    pub const CANONICAL: Self = Self {
        sample_rate_hz: 48_000,
        channels: 1,
        sample_format: SampleFormat::Signed16LittleEndian,
    };

    pub const FALLBACK_44K1: Self = Self {
        sample_rate_hz: 44_100,
        channels: 1,
        sample_format: SampleFormat::Signed16LittleEndian,
    };

    pub fn validate(self) -> Result<(), PcmError> {
        if self.channels != 1 {
            return Err(PcmError::UnsupportedChannels);
        }
        if self.sample_format != SampleFormat::Signed16LittleEndian {
            return Err(PcmError::UnsupportedSampleFormat);
        }
        if self.sample_rate_hz != 48_000 && self.sample_rate_hz != 44_100 {
            return Err(PcmError::UnsupportedSampleRate);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PcmError {
    UnsupportedSampleRate,
    UnsupportedChannels,
    UnsupportedSampleFormat,
    EmptyBlock,
    FrameCountOverflow,
    PayloadLengthMismatch,
    OutputLengthMismatch,
}

pub struct PcmBlockView<'a> {
    pub format: PcmFormat,
    pub frame_count: u32,
    pub payload_s16le: &'a [u8],
}

impl PcmBlockView<'_> {
    pub fn validate(&self) -> Result<(), PcmError> {
        self.format.validate()?;
        if self.frame_count == 0 {
            return Err(PcmError::EmptyBlock);
        }
        let expected = (self.frame_count as usize)
            .checked_mul(2)
            .ok_or(PcmError::FrameCountOverflow)?;
        if self.payload_s16le.len() != expected {
            return Err(PcmError::PayloadLengthMismatch);
        }
        Ok(())
    }
}

/// Decode into caller-owned storage. No allocation occurs and output is not
/// modified until format, frame count, and payload size have all validated.
pub fn decode_mono_s16le(block: PcmBlockView<'_>, output: &mut [i16]) -> Result<(), PcmError> {
    block.validate()?;
    if output.len() != block.frame_count as usize {
        return Err(PcmError::OutputLengthMismatch);
    }
    let chunks = block.payload_s16le.as_chunks::<2>().0;
    for (sample, bytes) in output.iter_mut().zip(chunks) {
        *sample = i16::from_le_bytes(*bytes);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_locked_rate_and_fallback_only() {
        assert_eq!(PcmFormat::CANONICAL.validate(), Ok(()));
        assert_eq!(PcmFormat::FALLBACK_44K1.validate(), Ok(()));
        assert_eq!(
            PcmFormat { sample_rate_hz: 96_000, ..PcmFormat::CANONICAL }.validate(),
            Err(PcmError::UnsupportedSampleRate),
        );
    }

    #[test]
    fn decodes_little_endian_without_allocating() {
        let block = PcmBlockView {
            format: PcmFormat::CANONICAL,
            frame_count: 2,
            payload_s16le: &[0x01, 0x00, 0xFE, 0xFF],
        };
        let mut output = [0i16; 2];
        assert_eq!(decode_mono_s16le(block, &mut output), Ok(()));
        assert_eq!(output, [1, -2]);
    }

    #[test]
    fn rejects_truncated_payload_before_output_mutation() {
        let block = PcmBlockView {
            format: PcmFormat::CANONICAL,
            frame_count: 2,
            payload_s16le: &[0x01, 0x00, 0xFE],
        };
        let mut output = [77i16; 2];
        assert_eq!(
            decode_mono_s16le(block, &mut output),
            Err(PcmError::PayloadLengthMismatch),
        );
        assert_eq!(output, [77, 77]);
    }
}

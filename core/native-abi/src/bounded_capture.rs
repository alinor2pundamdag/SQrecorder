//! Fixed-capacity PCM ingress queue. Overflow fails closed and records an integrity flag.
use std::sync::Mutex;
const MAX_QUEUE_BLOCKS:u32=256;
const MAX_BLOCK_BYTES:u32=256*1024;
#[derive(Clone,Copy,Debug,PartialEq,Eq)] pub enum CaptureStatus{Running,Stopping,Stopped,Failed}
#[derive(Clone,Copy,Debug,PartialEq,Eq)] pub enum CaptureError{InvalidConfiguration,InvalidBlock,InvalidState,QueueOverflow,ResourcePoisoned}
#[derive(Clone,Copy,Debug,PartialEq,Eq)] pub struct PcmMetadata{pub sample_rate_hz:u32,pub channels:u16,pub sample_format:u16,pub frames:u32,pub first_frame_index:u64,pub monotonic_timestamp_ns:u64,pub capture_epoch:u64,pub sequence:u32}
struct Slot{bytes:Box<[u8]>,len:usize,metadata:Option<PcmMetadata>}
struct Inner{slots:Vec<Slot>,head:usize,tail:usize,queued:usize,status:CaptureStatus,integrity_overflow:bool}
/// Allocates every payload slot at construction; submit never grows the queue.
pub struct BoundedPcmQueue{capacity:usize,max_bytes:usize,inner:Mutex<Inner>}
impl BoundedPcmQueue{
 pub fn new(capacity:u32,max_block_frames:u32)->Result<Self,CaptureError>{
  if capacity==0||capacity>MAX_QUEUE_BLOCKS||max_block_frames==0||max_block_frames.checked_mul(2).filter(|v|*v<=MAX_BLOCK_BYTES).is_none(){return Err(CaptureError::InvalidConfiguration)}
  let max_bytes=(max_block_frames*2) as usize;let mut slots=Vec::new();slots.try_reserve_exact(capacity as usize).map_err(|_|CaptureError::InvalidConfiguration)?;
  for _ in 0..capacity{let mut bytes=Vec::new();bytes.try_reserve_exact(max_bytes).map_err(|_|CaptureError::InvalidConfiguration)?;bytes.resize(max_bytes,0);slots.push(Slot{bytes:bytes.into_boxed_slice(),len:0,metadata:None});}
  Ok(Self{capacity:capacity as usize,max_bytes,inner:Mutex::new(Inner{slots,head:0,tail:0,queued:0,status:CaptureStatus::Running,integrity_overflow:false})})
 }
 pub fn submit(&self,m:PcmMetadata,pcm:&[u8])->Result<(),CaptureError>{
  let expected=(m.frames as usize).checked_mul(2).ok_or(CaptureError::InvalidBlock)?;
  if (m.sample_rate_hz!=48000&&m.sample_rate_hz!=44100)||m.channels!=1||m.sample_format!=1||m.frames==0||expected!=pcm.len()||pcm.len()>self.max_bytes{return Err(CaptureError::InvalidBlock)}
  let mut i=self.inner.lock().map_err(|_|CaptureError::ResourcePoisoned)?;
  if i.status!=CaptureStatus::Running{return Err(CaptureError::InvalidState)}
  if i.queued==self.capacity{i.status=CaptureStatus::Failed;i.integrity_overflow=true;return Err(CaptureError::QueueOverflow)}
  let tail=i.tail;let slot=&mut i.slots[tail];slot.bytes[..pcm.len()].copy_from_slice(pcm);slot.len=pcm.len();slot.metadata=Some(m);
  i.tail=(tail+1)%self.capacity;i.queued+=1;Ok(())
 }
 pub fn pop_into(&self,out:&mut[u8])->Result<Option<(PcmMetadata,usize)>,CaptureError>{
  let mut i=self.inner.lock().map_err(|_|CaptureError::ResourcePoisoned)?;if i.queued==0{return Ok(None)}
  let head=i.head;let slot=&mut i.slots[head];if out.len()<slot.len{return Err(CaptureError::InvalidBlock)}
  out[..slot.len].copy_from_slice(&slot.bytes[..slot.len]);let m=slot.metadata.take().ok_or(CaptureError::InvalidBlock)?;let n=slot.len;slot.len=0;
  i.head=(head+1)%self.capacity;i.queued-=1;Ok(Some((m,n)))
 }
 pub fn request_stop(&self)->Result<(),CaptureError>{let mut i=self.inner.lock().map_err(|_|CaptureError::ResourcePoisoned)?;if i.status!=CaptureStatus::Running{return Err(CaptureError::InvalidState)}i.status=CaptureStatus::Stopping;Ok(())}
 pub fn mark_stopped(&self)->Result<(),CaptureError>{let mut i=self.inner.lock().map_err(|_|CaptureError::ResourcePoisoned)?;if i.status!=CaptureStatus::Stopping||i.queued!=0{return Err(CaptureError::InvalidState)}i.status=CaptureStatus::Stopped;Ok(())}
 pub fn status(&self)->Result<CaptureStatus,CaptureError>{Ok(self.inner.lock().map_err(|_|CaptureError::ResourcePoisoned)?.status)}
 pub fn integrity_overflow(&self)->Result<bool,CaptureError>{Ok(self.inner.lock().map_err(|_|CaptureError::ResourcePoisoned)?.integrity_overflow)}
}
#[cfg(test)] mod tests{
 use super::*;fn m(seq:u32,frames:u32)->PcmMetadata{PcmMetadata{sample_rate_hz:48000,channels:1,sample_format:1,frames,first_frame_index:seq as u64*frames as u64,monotonic_timestamp_ns:seq as u64+1,capture_epoch:9,sequence:seq}}
 #[test]fn fifo_preserves_pcm(){let q=BoundedPcmQueue::new(2,4).unwrap();q.submit(m(0,2),&[1,2,3,4]).unwrap();q.submit(m(1,1),&[5,6]).unwrap();let mut o=[0;8];let(a,n)=q.pop_into(&mut o).unwrap().unwrap();assert_eq!(a.sequence,0);assert_eq!(&o[..n],&[1,2,3,4]);let(a,n)=q.pop_into(&mut o).unwrap().unwrap();assert_eq!(a.sequence,1);assert_eq!(&o[..n],&[5,6]);}
 #[test]fn overflow_fails_closed(){let q=BoundedPcmQueue::new(1,2).unwrap();q.submit(m(0,1),&[0,0]).unwrap();assert_eq!(q.submit(m(1,1),&[1,1]),Err(CaptureError::QueueOverflow));assert_eq!(q.status().unwrap(),CaptureStatus::Failed);assert!(q.integrity_overflow().unwrap());assert_eq!(q.submit(m(2,1),&[2,2]),Err(CaptureError::InvalidState));}
 #[test]fn invalid_shape_rejected(){let q=BoundedPcmQueue::new(2,8).unwrap();assert_eq!(q.submit(m(0,2),&[1,2]),Err(CaptureError::InvalidBlock));}
 #[test]fn stop_requires_drain(){let q=BoundedPcmQueue::new(2,4).unwrap();q.submit(m(0,1),&[0,0]).unwrap();q.request_stop().unwrap();assert_eq!(q.mark_stopped(),Err(CaptureError::InvalidState));let mut o=[0;8];q.pop_into(&mut o).unwrap();q.mark_stopped().unwrap();assert_eq!(q.status().unwrap(),CaptureStatus::Stopped);}
}
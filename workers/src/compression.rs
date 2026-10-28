//! Zstd decoding is incremental: one encoded block plus a bounded history window.
use crate::error::{Error, Result};
use futures_util::{Stream, StreamExt};
use ruzstd::decoding::{BlockDecodingStrategy, FrameDecoder};
use std::{
    io::{Cursor, Read},
    pin::Pin,
};

pub type BodyStream = Pin<Box<dyn Stream<Item = Result<Vec<u8>>>>>;
const MAX_WINDOW: u64 = 8 * 1024 * 1024;
const MAX_BLOCK: usize = 128 * 1024;
const MAX_FRAMES: usize = 1024;

pub fn body(
    request: &mut worker::Request,
    wire_limit: u64,
    decoded_limit: u64,
) -> Result<BodyStream> {
    let encoding = request
        .headers()
        .get("content-encoding")?
        .unwrap_or_else(|| "identity".into());
    if encoding != "identity" && encoding != "zstd" {
        return Err(Error::new(415, "unsupported request encoding"));
    }
    let stream = request
        .stream()?
        .map(|chunk| chunk.map_err(|e| Error::new(400, e)));
    let input = Input {
        stream: Box::pin(stream),
        pending: Vec::new(),
        offset: 0,
        read: 0,
        limit: wire_limit,
    };
    if encoding == "identity" {
        return Ok(Box::pin(async_stream::try_stream! {
            let mut input=input;
            let mut decoded=0;
            while let Some(chunk)=input.take(64*1024).await? {
                charge(&mut decoded,chunk.len(),decoded_limit)?;
                yield chunk;
            }
        }));
    }
    Ok(Box::pin(decode(input, decoded_limit)))
}
fn charge(total: &mut u64, bytes: usize, limit: u64) -> Result<()> {
    *total = total
        .checked_add(bytes as u64)
        .ok_or_else(|| Error::new(413, "upload is too large"))?;
    if *total > limit {
        return Err(Error::new(
            413,
            "upload exceeds declared or configured size",
        ));
    }
    Ok(())
}
struct Input {
    stream: BodyStream,
    pending: Vec<u8>,
    offset: usize,
    read: u64,
    limit: u64,
}
impl Input {
    async fn take(&mut self, max: usize) -> Result<Option<Vec<u8>>> {
        while self.offset == self.pending.len() {
            match self.stream.next().await {
                Some(chunk) => {
                    self.pending = chunk?;
                    self.offset = 0;
                    charge(&mut self.read, self.pending.len(), self.limit)?;
                }
                None => return Ok(None),
            }
        }
        let end = self.pending.len().min(self.offset + max);
        let chunk = self.pending[self.offset..end].to_vec();
        self.offset = end;
        Ok(Some(chunk))
    }
    async fn exact(&mut self, length: usize) -> Result<Vec<u8>> {
        let mut result = Vec::with_capacity(length);
        while result.len() < length {
            result.extend(
                self.take(length - result.len())
                    .await?
                    .ok_or_else(|| Error::new(400, "truncated zstd frame"))?,
            );
        }
        Ok(result)
    }
}
fn decode(mut input: Input, limit: u64) -> impl Stream<Item = Result<Vec<u8>>> {
    async_stream::try_stream! {
        let mut decoded=0;
        let mut frames=0;
        loop {
            let Some(prefix)=input.take(4).await? else {
                if frames==0 {Err(Error::new(400,"empty zstd stream"))?;}
                break;
            };
            let mut magic=prefix;
            if magic.len()<4 {magic.extend(input.exact(4-magic.len()).await?);}
            frames+=1;
            if frames>MAX_FRAMES {Err(Error::new(400,"too many zstd frames"))?;}
            let magic_number=u32::from_le_bytes(magic.as_slice().try_into().unwrap());
            if (0x184D2A50..=0x184D2A5F).contains(&magic_number) {
                let mut remaining=u32::from_le_bytes(input.exact(4).await?.try_into().unwrap()) as usize;
                while remaining>0 {
                    let chunk=input.take(remaining.min(64*1024)).await?.ok_or_else(|| Error::new(400,"truncated zstd skippable frame"))?;
                    remaining-=chunk.len();
                }
                continue;
            }
            if magic_number!=0xFD2FB528 {Err(Error::new(400,"invalid zstd frame magic"))?;}
            let descriptor=input.exact(1).await?[0];
            let single=descriptor&0x20!=0;
            let dictionary_size=[0,1,2,4][(descriptor&3) as usize];
            let content_size=match descriptor>>6 {0=>usize::from(single),1=>2,2=>4,_=>8};
            let mut header=magic;
            header.push(descriptor);
            header.extend(input.exact(usize::from(!single)+dictionary_size+content_size).await?);
            let mut decoder=FrameDecoder::new();
            decoder.set_max_window_size(MAX_WINDOW);
            decoder.reset(Cursor::new(header)).map_err(|e| Error::new(400,format!("invalid zstd frame: {e}")))?;
            let mut frame_decoded=0u64;
            loop {
                let mut block=input.exact(3).await?;
                let bits=u32::from(block[0]) | (u32::from(block[1])<<8) | (u32::from(block[2])<<16);
                let last=bits&1!=0;
                let kind=(bits>>1)&3;
                let size=(bits>>3) as usize;
                if kind==3 || size>MAX_BLOCK {Err(Error::new(400,"invalid zstd block"))?;}
                block.extend(input.exact(if kind==1 {1}else{size}).await?);
                if last && descriptor&4!=0 {block.extend(input.exact(4).await?);}
                decoder.decode_blocks(Cursor::new(block),BlockDecodingStrategy::UptoBlocks(1))
                    .map_err(|e| Error::new(400,format!("invalid zstd block: {e}")))?;
                while decoder.can_collect()>0 {
                    let mut out=vec![0;decoder.can_collect().min(64*1024)];
                    let n=decoder.read(&mut out).map_err(|e| Error::new(400,e))?;
                    out.truncate(n);
                    charge(&mut decoded,n,limit)?;
                    frame_decoded+=n as u64;
                    yield out;
                }
                if last {
                    if (single || descriptor>>6!=0) && decoder.content_size()!=frame_decoded {
                        Err(Error::new(400,"zstd frame content size mismatch"))?;
                    }
                    if descriptor&4!=0 && decoder.get_checksum_from_data()!=decoder.get_calculated_checksum() {
                        Err(Error::new(400,"zstd checksum mismatch"))?;
                    }
                    break;
                }
            }
        }
    }
}

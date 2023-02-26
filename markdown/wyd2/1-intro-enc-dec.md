---
title: Introduction to WYD encryption and decryption using Rust
published: true
description: An article used to introduce the WYD encryption and decryption using Rust
tags: 'rust, wyd, encryption, mmorpg'
cover_image: null
canonical_url: null
---

This article is the first of a MMORPG's WYD open source server development series.

> This series will written with the help of Github Copilot and be revised with ChatGPT.

## Background

I have started my life into the programming world, as many others, building tools, hacks and bots for MMORPG's games. In my case it was the MMORPG game called "With Your Destiny" a.k.a. W.Y.D.. After a while in the hidden side, I received an offer to work in the server side of the game, I accepted it, and many Assembly, C and C++ code later, I was able to understand the game's core and how it works. At a certain point, just reversing and hooking stuff was not enough to accomplish what we wanted, so I started to build our own server from scratch. I have (re)built our data server and started to work on the game server, but I have never finished it.

> I have left the company and the project, but I have never stopped thinking about it. I have always wanted to finish it, but I have never had the time to do it. I have always wanted to share my knowledge with the community, but I have never had the time to do it. I have always wanted to open source the project, but I have never had the time to do it. I have always wanted to write about it, but I have never had the time to do it. (_This paragraph was suggested as it is by Copilot and it makes sense, so I will left it here._)

Back to the me, many years has passed since that point, web development has become my main job, then reverse engineer again, more professional this time, but I never stopped touching in that server project. Align with that I recently started to learn Rust and decided to get back to the project using Rust, so after finishing the book [Rust for Rustaceans](https://nostarch.com/rust-rustaceans) I decided to start this series of articles.

## Disclaimer

This series will not cover all the game details, it is intended to be an extension from my note books about the process that I will walkthrough while (re)writing the data and game servers in Rust.

## WYD packet structure

The WYD packets are structured using C default alignment, therefore in Rust it requires `#[repr(C)]` to keep the consistency. The minimal packet structure is composed by 12 bytes and all other packets are an extension of the minimal structure, it can be represented as the following struct:

```C++
struct MsgHeader {
  uint16_t size_;      // Packet size
  uint8_t key_;        // Key used as seed for enc/dec
  uint8_t hash_;       // Hash generated to validate the process
  int16_t code_;       // Internal packet identifier
  int16_t index_;      // Index from the user that sent the packet
  uint32_t timestamp_; // Timestamp
};
```

```rust
#[repr(C)]
pub struct MsgHeader {
    size: u16,      // Packet size
    key: u8,        // Key used as seed for enc/dec
    hash: u8,       // Hash generated to validate the process
    code: i16,      // Internal packet identifier
    index: i16,     // Index from the user that sent the packet
    timestamp: u32, // Timestamp
}
```

## WYD encryption and decryption

The WYD encryption and decryption is a series of simple arithmetic operations, that uses a pre-defined array of 512 bytes keys, and a byte as seed. The encryption and decryption is done per byte, and the seed is incremented by 1 after each block.

The C++ version of the **encryption** function is the following:

```C++
uint8_t keys[512];

void encrypt(MsgHeader *packet) {
  uint8_t *ptr = reinterpret_cast<uint8_t *>(packet);
  uint16_t j = 4;
  uint8_t seed = rand() % 256;
  int key = (uint8_t)keys[seed << 1];
  do {
    uint32_t mappedKey = keys[((key % 256) << 1) + 1];
    switch (j & 3) {
    case 0:
      ptr[j] = ptr[j] + (uint32_t)(mappedKey << 1);
      break;
    case 1:
      ptr[j] = ptr[j] - (uint32_t)(mappedKey >> 3);
      break;
    case 2:
      ptr[j] = ptr[j] + (uint32_t)(mappedKey << 2);
      break;
    case 3:
      ptr[j] = ptr[j] - (uint32_t)(mappedKey >> 5);
      break;
    }
    j++;
    key++;
  } while (j < packet->size_);
  packet->key_ = seed;
}
```

The C++ version of the **decryption** function is the following:

```C++
uint8_t keys[512];

void encrypt(MsgHeader *packet) {
  uint8_t *ptr = reinterpret_cast<uint8_t *>(packet);
  uint16_t j = 4;
  int key = (uint8_t)keys[packet->key_ << 1];
  do {
    uint32_t mappedKey = keys[((key % 256) << 1) + 1];
    switch (j & 3) {
    case 0:
      ptr[j] = ptr[j] - (uint8_t)(mappedKey << 1);
      break;
    case 1:
      ptr[j] = ptr[j] + (uint8_t)((int32_t)mappedKey >> 3);
      break;
    case 2:
      ptr[j] = ptr[j] - (uint8_t)(mappedKey << 2);
      break;
    case 3:
      ptr[j] = ptr[j] + (uint8_t)((int32_t)mappedKey >> 5);
      break;
    }
    j++;
    key++;
  } while (j < packet->size_);
}
```

You might have noticed that encryption and decryption are very similar, but naturally to get the original value in the decryption you need to do the opposite operation in the encryption. The other differences are:

1) the encryption uses a random seed;
2) the decryption uses the seed from the packet;
3) the decryption needs to careful consider overflow and underflow.

## Converting the decryption into Rust code

This is the thing first I have focused while (re)writing the encryption and decryption in Rust, and I have found a way to do it in Rust, actually I have found three ways to do that and in this article I will talk a bit about each one of them and my final decision. (I have a certain hope that some Rust experts might bump into this and give me some hints.)

Using Rust you can't _just_ `reinterpret_cast` a struct to a byte array, and since I'm pretty new to this, SO I have started by considering an input of `&mut Vec<u8>` and focused in doing the byte arithmetics in Rust.

### Dummy version

The first version I made was the most _Rust++_ version possible, build a huge unsafe block and play with raw pointer the same way I was doing in C++. The code turns out to be:

```rust
    pub fn decrypt(raw_data: &mut Vec<u8>, keys: &[u8]) -> Vec<u8> {
        let mut index: isize = 0;
        let end_index: isize = raw_data.len() as isize;
        let ptr: *const u8 = raw_data.as_ptr();
        let min_size = mem::size_of::<MsgHeader>() as isize;

        while (end_index - index) >= min_size {
            // SAFETY: header is always at least size_of<MsgHeader> sized
            unsafe {
                let current_ptr = ptr.offset(index as isize) as *mut u8;
                let header = current_ptr as *const MsgHeader;
                let packet_size = (*header).size as isize;
                // SAFETY: packet_size is always less or equal to number of remaining bytes
                if (end_index - index) >= packet_size {
                    let mut j = 4;
                    let mut key = keys[((*header).key as usize) << 1] as usize;
                    while j < packet_size {
                        let mapped_key = keys[((key % 256) << 1) + 1] as u32;
                        let off = current_ptr.offset(j as isize) as *mut u8;
                        match j & 3 {
                            0 => *off = (*off).wrapping_sub((mapped_key << 1) as u8),
                            1 => *off = (*off).wrapping_add((mapped_key as i32 >> 3) as u8),
                            2 => *off = (*off).wrapping_sub((mapped_key << 2) as u8),
                            _ => *off = (*off).wrapping_add((mapped_key as i32 >> 5) as u8),
                        }
                        j += 1;
                        key += 1;
                    }
                    index += packet_size;
                } else {
                    index += end_index - index;
                }
            }
        }
        raw_data.to_vec()
    }
```

### Safe version

The second version I built was after watching all [Crust of Rust](https://www.youtube.com/watch?v=rAl-9HwD858&list=PLqbS7AVVErFiWDOAVrPt7aYmnuuOLYvOa) videos, the main difference is does **not** use raw pointers, instead it uses `Cursor`, it's _slightly_ slower(probably not relevant in the production code) but it's much more readable and safer(literally no `unsafe` code). This version is the following:

```rust
    pub fn decrypt_cursor(raw_data: &mut Vec<u8>, keys: &[u8]) -> Vec<u8> {
        let mut buffer = Cursor::new(raw_data);
        let mut index = 0 as usize;
        let end_index = buffer.get_ref().len();
        let min_size = mem::size_of::<MsgHeader>();

        while (end_index - index) >= min_size {
            let packet_size = buffer.get_u16_le() as usize;
            if (end_index - index) >= packet_size {
                let dst = &mut buffer.get_mut()[index..index + packet_size];
                let mut key = keys[(dst[2] as usize) << 1] as usize;
                for i in 4..packet_size {
                    let mapped_key = keys[((key % 256) << 1) + 1] as u32;
                    match i & 3 {
                        0 => dst[i] = (dst[i]).wrapping_sub((mapped_key << 1) as u8),
                        1 => dst[i] = (dst[i]).wrapping_add((mapped_key as i32 >> 3) as u8),
                        2 => dst[i] = (dst[i]).wrapping_sub((mapped_key << 2) as u8),
                        _ => dst[i] = (dst[i]).wrapping_add((mapped_key as i32 >> 5) as u8),
                    }
                    key += 1;
                }
                index += packet_size;
            } else {
                index += end_index - index;
            }
            buffer.set_position(index as u64);
        }
        buffer.get_ref().to_vec()
    }
```

### Final version

The third version I built after started checking how I was going to use that in a `connection/frame` layer, and it's basically the second version, but with more direct input now. This is likely the version that will be embedded into the server, unless I get better suggestions. Check it below:

```rust
    pub fn decode(&self, buffer: &mut Cursor<&mut [u8]>) {
        let packet_size = buffer.get_u16_le() as usize;
        let dst = buffer.get_mut();
        let mut key = self.keys[(dst[2] as usize) << 1] as usize;
        for i in 4..packet_size {
            let mapped_key = self.keys[((key % 256) << 1) + 1] as u32;
            match i & 3 {
                0 => dst[i] = (dst[i]).wrapping_sub((mapped_key << 1) as u8),
                1 => dst[i] = (dst[i]).wrapping_add((mapped_key as i32 >> 3) as u8),
                2 => dst[i] = (dst[i]).wrapping_sub((mapped_key << 2) as u8),
                _ => dst[i] = (dst[i]).wrapping_add((mapped_key as i32 >> 5) as u8),
            }
            key += 1;
        }
    }
```

All theses versions, but the last, can be found [here](https://github.com/raphaelts3/wyd2encdec/blob/cc34f1f4a1056d54c79430985dbe8ca2092cd1bc/rust/src/lib.rs). The last one will be shared in the future when I start to publish the server code.

## Thoughts on C++ vs Rust so far

- First of all, you must consider that I am implementing something that _must_ respect the original algorithm;
- The `unsafe` can be really tempting if you are coming from C/C++, but I think that it's a good thing that Rust forces you to think about the safety of your code;
- The _dummy_ version was pretty straightforward to implement, but the _safe_ version was a bit tricker to get to, because I was not familiar with the ecosystem, and there was not much samples of what I was trying to do.
  - _(However, I honestly think that I have started with something that isn't a day-to-day thing, so that also shreds the amount of samples in the web.)_

That said, I am quite happy with the latest version, even thought it is not the most performant, it's the most readable and does not use any `unsafe`.

## Final thoughts

The next challenges should be related to easily convert a `MsgHeader`-like struct into a `&[u8]` and vice-versa, and to _extend_ it to the dozens of other packets that the game has, but that's a topic for the future.

The source code of the algorithms discussed here can be found in [this](https://github.com/raphaelts3/wyd2encdec) repository. There you might find it in C++, C#, Java, Go, PHP, Rust, and feel free to contribute to the project with your own implementation.

_I don't have any schedule to this series, but I do hope that starting this series will help me to keep working on the project and to keep sharing my knowledge with the community._

## References

- [My articles repository](https://github.com/raphaelts3/articles).
- [The WYD2EncDec repository](https://github.com/raphaelts3/wyd2encdec).
- The [Rust for Rustaceans](https://nostarch.com/rust-rustaceans) book.
- The [Rust Programming Language](https://doc.rust-lang.org/book/) book.

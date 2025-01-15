use napi::{bindgen_prelude::Buffer, Result};
use napi_derive::napi;

const DELTA: u32 = 0x9e3779b9;
#[napi]
pub const TEA_BLOCK_LEN: u32 = 8;

#[napi]
pub const TEA_KEY_LEN: u32 = 16;

fn tea_encrypt(v: &mut [u32; 2], k: &[u32; 4], iter: usize) {
  let mut v0 = v[0];
  let mut v1 = v[1];
  let mut sum: u32 = 0;
  for _ in 0..iter {
    sum = sum.wrapping_add(DELTA);
    v0 = v0.wrapping_add(
      ((v1 << 4).wrapping_add(k[0])) ^ (v1.wrapping_add(sum)) ^ ((v1 >> 5).wrapping_add(k[1])),
    );
    v1 = v1.wrapping_add(
      ((v0 << 4).wrapping_add(k[2])) ^ (v0.wrapping_add(sum)) ^ ((v0 >> 5).wrapping_add(k[3])),
    );
  }
  v[0] = v0;
  v[1] = v1;
}

fn tea_decrypt(v: &mut [u32; 2], k: &[u32; 4], iter: usize) {
  let mut v0 = v[0];
  let mut v1 = v[1];
  let mut sum = DELTA.wrapping_mul(iter as u32);
  for _ in 0..iter {
    v1 = v1.wrapping_sub(
      ((v0 << 4).wrapping_add(k[2])) ^ (v0.wrapping_add(sum)) ^ ((v0 >> 5).wrapping_add(k[3])),
    );
    v0 = v0.wrapping_sub(
      ((v1 << 4).wrapping_add(k[0])) ^ (v1.wrapping_add(sum)) ^ ((v1 >> 5).wrapping_add(k[1])),
    );
    sum = sum.wrapping_sub(DELTA);
  }
  v[0] = v0;
  v[1] = v1;
}

#[napi(js_name = "teaDecrypt")]
pub fn tea_decrypt_js(value: Buffer, key: Buffer, iter: u32) -> Result<Buffer> {
  let mut value_data: Vec<u8> = value.into();
  let mut key_data: Vec<u8> = key.into();

  if key_data.len() > TEA_KEY_LEN as usize {
    key_data.truncate(TEA_KEY_LEN as usize);
  } else if key_data.len() < TEA_KEY_LEN as usize {
    key_data.resize(TEA_KEY_LEN as usize, 0);
  }

  let cnt = value_data.len() / TEA_BLOCK_LEN as usize;
  let mut tmp = [0u32; 2];
  let key: [u32; 4] = bytemuck::cast_slice(&key_data)[..4]
    .try_into()
    .expect("Key slice must be exactly 4 elements");

  for i in 0..cnt {
    tmp.copy_from_slice(bytemuck::cast_slice(
      &value_data[i * TEA_BLOCK_LEN as usize..(i + 1) * TEA_BLOCK_LEN as usize],
    ));
    tea_decrypt(&mut tmp, &key, iter as usize);
    value_data[i * TEA_BLOCK_LEN as usize..(i + 1) * TEA_BLOCK_LEN as usize]
      .copy_from_slice(bytemuck::cast_slice(&tmp));
  }

  Ok(Buffer::from(value_data))
}

#[napi(js_name = "teaEncrypt")]
pub fn tea_encrypt_js(value: Buffer, key: Buffer, iter: u32) -> Result<Buffer> {
  let mut value_data: Vec<u8> = value.into();
  let mut key_data: Vec<u8> = key.into();

  if key_data.len() > TEA_KEY_LEN as usize {
    key_data.truncate(TEA_KEY_LEN as usize);
  } else if key_data.len() < TEA_KEY_LEN as usize {
    key_data.resize(TEA_KEY_LEN as usize, 0);
  }

  let cnt = value_data.len() / TEA_BLOCK_LEN as usize;
  let mut tmp = [0u32; 2];
  let key: [u32; 4] = bytemuck::cast_slice(&key_data)[..4]
    .try_into()
    .expect("Key slice must be exactly 4 elements");

  for i in 0..cnt {
    tmp.copy_from_slice(bytemuck::cast_slice(
      &value_data[i * TEA_BLOCK_LEN as usize..(i + 1) * TEA_BLOCK_LEN as usize],
    ));
    tea_encrypt(&mut tmp, &key, iter as usize);
    value_data[i * TEA_BLOCK_LEN as usize..(i + 1) * TEA_BLOCK_LEN as usize]
      .copy_from_slice(bytemuck::cast_slice(&tmp));
  }

  Ok(Buffer::from(value_data))
}

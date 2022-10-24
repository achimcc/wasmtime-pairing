#![no_std]
#![feature(test)]
extern crate test;

use anyhow::{anyhow, Result};
use num_bigint::BigUint;
use sp_std::vec::Vec;
use wasmtime::*;

const P_G1: i32 = 42104;
const P_G2: i32 = 42392;
struct WasmInstance {
    memory: Memory,
    instance: Instance,
    store: Store<()>,
}

impl WasmInstance {
    fn from_file(path: &str) -> Result<Self, anyhow::Error> {
        // An engine stores and configures global compilation settings like
        // optimization level, enabled wasm features, etc.
        let engine = Engine::default();
        // We start off by creating a `Module` which represents a compiled form
        // of our input wasm module. In this case it'll be JIT-compiled after
        // we parse the text format.
        let module = Module::from_file(&engine, path)?;

        // A `Store` is what will own instances, functions, globals, etc. All wasm
        // items are stored within a `Store`, and it's what we'll always be using to
        // interact with the wasm world. Custom data can be stored in stores but for
        // now we just use `()`.
        let mut store = Store::new(&engine, ());

        let memory = Memory::new(&mut store, MemoryType::new(30, None)).unwrap();

        // For host-provided functions it's recommended to use a `Linker` which does
        // name-based resolution of functions.
        let mut linker = Linker::new(&engine);

        linker.define("env", "memory", memory)?;

        // With a compiled `Module` we can then instantiate it, creating
        // an `Instance` which we can actually poke at functions on.
        let instance = linker.instantiate(&mut store, &module)?;
        Ok(Self {
            memory,
            instance,
            store,
        })
    }

    fn from_montgomery(&mut self, from: i32, to: i32) {
        self.instance
            .get_export(&self.store, "ftm_fromMontgomery")
            .and_then(Extern::into_func)
            .ok_or_else(|| anyhow!("could not find function \"ftm_fromMontgomery\""))
            .unwrap()
            .typed::<(i32, i32), ()>(&mut self.store)
            .unwrap()
            .call(&mut self.store, (from, to))
            .unwrap();
    }

    fn to_montgomery(&mut self, from: i32, to: i32) {
        self.instance
            .get_export(&self.store, "ftm_toMontgomery")
            .and_then(Extern::into_func)
            .ok_or_else(|| anyhow!("could not find function \"ftm_toMontgomery\""))
            .unwrap()
            .typed::<(i32, i32), ()>(&mut self.store)
            .unwrap()
            .call(&mut self.store, (from, to))
            .unwrap();
    }

    fn compute_pairing(&mut self, p_g1: i32, p_g2: i32, p_res: i32) {
        self.instance
            .get_export(&self.store, "bls12381_pairing")
            .and_then(Extern::into_func)
            .ok_or_else(|| anyhow!("could not find function \"bls12381_pairing\""))
            .unwrap()
            .typed::<(i32, i32, i32), ()>(&mut self.store)
            .unwrap()
            .call(&mut self.store, (p_g1, p_g2, p_res))
            .unwrap();
    }

    fn g1m_neg(&mut self, from: i32, to: i32) {
        self.instance
            .get_export(&self.store, "g1m_neg")
            .and_then(Extern::into_func)
            .ok_or_else(|| anyhow!("could not find function \"g1m_neg\""))
            .unwrap()
            .typed::<(i32, i32), ()>(&mut self.store)
            .unwrap()
            .call(&mut self.store, (from, to))
            .unwrap();
    }

    fn ftm_conjugate(&mut self, from: i32, to: i32) {
        self.instance
            .get_export(&self.store, "ftm_conjugate")
            .and_then(Extern::into_func)
            .ok_or_else(|| anyhow!("could not find function \"ftm_conjugate\""))
            .unwrap()
            .typed::<(i32, i32), ()>(&mut self.store)
            .unwrap()
            .call(&mut self.store, (from, to))
            .unwrap();
    }

    fn g2m_neg(&mut self, from: i32, to: i32) {
        self.instance
            .get_export(&self.store, "g2m_neg")
            .and_then(Extern::into_func)
            .ok_or_else(|| anyhow!("could not find function \"g2m_neg\""))
            .unwrap()
            .typed::<(i32, i32), ()>(&mut self.store)
            .unwrap()
            .call(&mut self.store, (from, to))
            .unwrap();
    }

    fn get_f12(&mut self, p_f12: i32, in_montgomery: bool) -> [[[BigUint; 2]; 3]; 2] {
        if !in_montgomery {
            self.from_montgomery(p_f12, p_f12);
        }
        let data: Vec<u8> = self.memory.data(&self.store).to_vec();
        if !in_montgomery {
            self.to_montgomery(p_f12, p_f12)
        };
        let p_f12 = p_f12 as usize;
        [
            [
                [
                    from_le(shift(p_f12, &data, 0)),
                    from_le(shift(p_f12, &data, 1)),
                ],
                [
                    from_le(shift(p_f12, &data, 2)),
                    from_le(shift(p_f12, &data, 3)),
                ],
                [
                    from_le(shift(p_f12, &data, 4)),
                    from_le(shift(p_f12, &data, 5)),
                ],
            ],
            [
                [
                    from_le(shift(p_f12, &data, 6)),
                    from_le(shift(p_f12, &data, 7)),
                ],
                [
                    from_le(shift(p_f12, &data, 8)),
                    from_le(shift(p_f12, &data, 9)),
                ],
                [
                    from_le(shift(p_f12, &data, 10)),
                    from_le(shift(p_f12, &data, 11)),
                ],
            ],
        ]
    }

    fn get_f12_u8(&mut self, p_f12: i32, in_montgomery: bool) -> Vec<u8> {
        if !in_montgomery {
            self.from_montgomery(p_f12, p_f12);
        }
        let data: &[u8] = self.memory.data(&self.store);
        let result = data[(p_f12 as usize)..(p_f12 as usize + 12 * 48)].to_vec();
        if !in_montgomery {
            self.to_montgomery(p_f12, p_f12)
        };
        let p_f12 = p_f12 as usize;
        result
    }

    fn g1(&self) -> [Vec<u8>; 3] {
        let data: Vec<u8> = self.memory.data(&self.store).to_vec();
        [
            shift(P_G1 as usize, &data, 0),
            shift(P_G1 as usize, &data, 1),
            shift(P_G1 as usize, &data, 2),
        ]
    }

    fn g2(&self) -> [[[Vec<u8>; 2]; 1]; 3] {
        let p_g2 = P_G2 as usize;
        let data: Vec<u8> = self.memory.data(&self.store).to_vec();
        [
            [[shift(p_g2, &data, 0), shift(p_g2, &data, 1)]],
            [[shift(p_g2, &data, 2), shift(p_g2, &data, 3)]],
            [[shift(p_g2, &data, 4), shift(p_g2, &data, 5)]],
        ]
    }

    fn write_to_memory(&mut self, p_location: i32, buffer: &[u8]) {
        self.memory
            .write(&mut self.store, p_location as usize, buffer);
    }

    fn read_from_memory(&self, p_location: i32, range: usize) -> &[u8] {
        let data: &[u8] = self.memory.data(&self.store);
        let p_location = p_location as usize;
        &data[p_location..p_location + range]
    }
}

fn shift(start: usize, data: &[u8], pos: usize) -> Vec<u8> {
    let n8q: usize = 48;
    data[(start + pos * n8q)..(start + (pos + 1) * n8q)].to_vec()
}

fn to_le(str: &str) -> Vec<u8> {
    BigUint::to_bytes_le(&str.parse::<BigUint>().unwrap())
}

fn from_le(vec: Vec<u8>) -> BigUint {
    BigUint::from_bytes_le(&vec)
}

pub fn wasm_pairing(a: &[u8], b: &[u8]) -> Vec<u8> {
    let mut wasm = WasmInstance::from_file("bls12381.wasm").expect("");
    let p_a: i32 = 125000;
    let p_b: i32 = 126000;
    let p_result: i32 = 127000;
    wasm.write_to_memory(p_a, a);
    wasm.write_to_memory(p_a, b);
    wasm.compute_pairing(p_a, p_b, p_result);
    wasm.get_f12_u8(p_result, true)
}

#[cfg(test)]

mod tests {
    use super::*;
    use test::Bencher;

    #[test]
    fn write_to_memory_works() {
        let mut wasm = WasmInstance::from_file("bls12381.wasm").expect("");
        let p_a_destination: i32 = 127000;
        let p_b_destination: i32 = 128000;
        let p_res1: i32 = 129000;
        let p_res2: i32 = 130000;
        let a = wasm.read_from_memory(P_G1, 3 * 48).to_vec();
        let b = wasm.read_from_memory(P_G2, 6 * 48).to_vec();
        wasm.write_to_memory(p_a_destination, &a);
        wasm.write_to_memory(p_b_destination, &b);
        wasm.compute_pairing(p_a_destination, p_b_destination, p_res1);
        wasm.compute_pairing(P_G1, P_G2, p_res2);
        let res1 = wasm.get_f12(p_res1, false);
        let res2 = wasm.get_f12(p_res2, false);
        assert_eq!(res1, res2);
    }

    #[test]
    fn paring_works() {
        let mut wasm = WasmInstance::from_file("bls12381.wasm").expect("");
        let p_result: i32 = 127000;
        wasm.compute_pairing(P_G1, P_G2, p_result);
        let result = wasm.get_f12(p_result, false);
        println!("result: {:?}", result);
        let result_montgomery = wasm.get_f12(p_result, true);
        println!("result in montgomery: {:?}", result_montgomery);
    }
    #[test]
    fn paring_is_unitary() {
        let mut wasm =
            WasmInstance::from_file("bls12381.wasm").expect("Failed to instantiate WASM");

        // Define memory location to which we write the computation results
        let p_n_g1: i32 = 125000;
        let p_n_g2: i32 = 126000;
        let p_p: i32 = 127000;
        let p_q: i32 = 128000;
        let p_r: i32 = 129000;

        // compute the pairing and write it to p_res location in memory
        wasm.g1m_neg(P_G1, p_n_g1);
        wasm.g2m_neg(P_G2, p_n_g2);
        wasm.compute_pairing(P_G1, P_G2, p_p);
        wasm.ftm_conjugate(p_p, p_p);
        wasm.compute_pairing(p_n_g1, P_G2, p_q);
        wasm.compute_pairing(P_G1, p_n_g2, p_r);
        let p = wasm.get_f12(p_p, false);
        let q = wasm.get_f12(p_q, false);
        let r = wasm.get_f12(p_r, false);
        assert_eq!(p, q);
        assert_eq!(q, r);
    }

    #[bench]
    fn bench_pairing(b: &mut Bencher) {
        let p_result: i32 = 129000;
        let mut wasm =
            WasmInstance::from_file("bls12381.wasm").expect("Failed to instantiate WASM");
        b.iter(|| wasm.compute_pairing(P_G1, P_G2, p_result));
    }

    #[bench]
    fn bench_instantiation(b: &mut Bencher) {
        b.iter(|| {
            let _ = WasmInstance::from_file("bls12381.wasm").expect("Failed to instantiate WASM");
        });
    }

    #[bench]
    fn bench_instantiate_and_pair(b: &mut Bencher) {
        let p_result: i32 = 129000;
        b.iter(|| {
            let mut wasm =
                WasmInstance::from_file("bls12381.wasm").expect("Failed to instantiate WASM");
            wasm.compute_pairing(P_G1, P_G2, p_result);
        });
    }
}

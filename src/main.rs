// use std::collections::HashMap;

// use simdutf8::avx512_dfa::T_LUT;
use simdutf8::shift_dfa::BYTE_CLASS_VARIANTS;
// use simdutf8::shift_dfa::ByteClass;
use simdutf8::shift_dfa::FORWARD_DFA_VARIANTS;
use simdutf8::shift_dfa::ror_transitions;

pub fn main() {
    // for c in 0..=255 {
    //     let transition = ror_transitions(ByteClass::from(c));
    //     println!("{:32b} 0x{:x}", transition, transition);
    //     // dbg!(ror_transitions(ByteClass::from(c)));
    // }
    for byte in BYTE_CLASS_VARIANTS {
        println!(
            "{:?}",
            FORWARD_DFA_VARIANTS.map(|state| state.transition(byte) as usize)
        );
    }
    for byte in BYTE_CLASS_VARIANTS {
        dbg!(byte as usize);
        let transition = ror_transitions(byte);
        println!("{:032b} 0x{:x}", transition, transition);
    }

    // let lut = T_LUT.map(u64::to_le_bytes);
    // let mut table: [[[u8; 7]; 13]; 13] = Default::default();
    // for i in 0..13 {
    //     for j in 0..13 {
    //         for k in 0..7 {
    //             table[i][j][k] = lut[j][lut[i][k] as usize];
    //         }
    //         println!("{i:3} {j:3} {:3} {:?}", (14 * i + j) % 128, table[i][j]);
    //     }
    // }
    // // for line in table {
    // //     println!("{:#x?}", line.map(u64::from_le_bytes));
    // // }
    // let mut counter = HashMap::<_, usize>::new();
    // table
    //     .iter()
    //     .flatten()
    //     .for_each(|transition| *counter.entry(transition).or_default() += 1);
    // println!("{}", counter.len());
    // for (k, v) in counter {
    //     println!("{:?}: {:?}", k, v);
    // }
}

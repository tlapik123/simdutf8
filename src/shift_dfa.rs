//! An UTF-8 validation implemented using a DFA.
//! Interpretation of the automaton is implemented using bit-shifts, achieving 1 byte / clock.

static S_LUT: [u64; 256] = [
    0x30c30c30c30c00,
    0x30c30c30c30c00,
    0x30c30c30c30c00,
    0x30c30c30c30c00,
    0x30c30c30c30c00,
    0x30c30c30c30c00,
    0x30c30c30c30c00,
    0x30c30c30c30c00,
    0x30c30c30c30c00,
    0x30c30c30c30c00,
    0x30c30c30c30c00,
    0x30c30c30c30c00,
    0x30c30c30c30c00,
    0x30c30c30c30c00,
    0x30c30c30c30c00,
    0x30c30c30c30c00,
    0x30c30c30c30c00,
    0x30c30c30c30c00,
    0x30c30c30c30c00,
    0x30c30c30c30c00,
    0x30c30c30c30c00,
    0x30c30c30c30c00,
    0x30c30c30c30c00,
    0x30c30c30c30c00,
    0x30c30c30c30c00,
    0x30c30c30c30c00,
    0x30c30c30c30c00,
    0x30c30c30c30c00,
    0x30c30c30c30c00,
    0x30c30c30c30c00,
    0x30c30c30c30c00,
    0x30c30c30c30c00,
    0x30c30c30c30c00,
    0x30c30c30c30c00,
    0x30c30c30c30c00,
    0x30c30c30c30c00,
    0x30c30c30c30c00,
    0x30c30c30c30c00,
    0x30c30c30c30c00,
    0x30c30c30c30c00,
    0x30c30c30c30c00,
    0x30c30c30c30c00,
    0x30c30c30c30c00,
    0x30c30c30c30c00,
    0x30c30c30c30c00,
    0x30c30c30c30c00,
    0x30c30c30c30c00,
    0x30c30c30c30c00,
    0x30c30c30c30c00,
    0x30c30c30c30c00,
    0x30c30c30c30c00,
    0x30c30c30c30c00,
    0x30c30c30c30c00,
    0x30c30c30c30c00,
    0x30c30c30c30c00,
    0x30c30c30c30c00,
    0x30c30c30c30c00,
    0x30c30c30c30c00,
    0x30c30c30c30c00,
    0x30c30c30c30c00,
    0x30c30c30c30c00,
    0x30c30c30c30c00,
    0x30c30c30c30c00,
    0x30c30c30c30c00,
    0x30c30c30c30c00,
    0x30c30c30c30c00,
    0x30c30c30c30c00,
    0x30c30c30c30c00,
    0x30c30c30c30c00,
    0x30c30c30c30c00,
    0x30c30c30c30c00,
    0x30c30c30c30c00,
    0x30c30c30c30c00,
    0x30c30c30c30c00,
    0x30c30c30c30c00,
    0x30c30c30c30c00,
    0x30c30c30c30c00,
    0x30c30c30c30c00,
    0x30c30c30c30c00,
    0x30c30c30c30c00,
    0x30c30c30c30c00,
    0x30c30c30c30c00,
    0x30c30c30c30c00,
    0x30c30c30c30c00,
    0x30c30c30c30c00,
    0x30c30c30c30c00,
    0x30c30c30c30c00,
    0x30c30c30c30c00,
    0x30c30c30c30c00,
    0x30c30c30c30c00,
    0x30c30c30c30c00,
    0x30c30c30c30c00,
    0x30c30c30c30c00,
    0x30c30c30c30c00,
    0x30c30c30c30c00,
    0x30c30c30c30c00,
    0x30c30c30c30c00,
    0x30c30c30c30c00,
    0x30c30c30c30c00,
    0x30c30c30c30c00,
    0x30c30c30c30c00,
    0x30c30c30c30c00,
    0x30c30c30c30c00,
    0x30c30c30c30c00,
    0x30c30c30c30c00,
    0x30c30c30c30c00,
    0x30c30c30c30c00,
    0x30c30c30c30c00,
    0x30c30c30c30c00,
    0x30c30c30c30c00,
    0x30c30c30c30c00,
    0x30c30c30c30c00,
    0x30c30c30c30c00,
    0x30c30c30c30c00,
    0x30c30c30c30c00,
    0x30c30c30c30c00,
    0x30c30c30c30c00,
    0x30c30c30c30c00,
    0x30c30c30c30c00,
    0x30c30c30c30c00,
    0x30c30c30c30c00,
    0x30c30c30c30c00,
    0x30c30c30c30c00,
    0x30c30c30c30c00,
    0x30c30c30c30c00,
    0x30c30c30c30c00,
    0x30c30c30c30c00,
    0x30c30c30c30c00,
    0x30492c061b0030,
    0x30492c061b0030,
    0x30492c061b0030,
    0x30492c061b0030,
    0x30492c061b0030,
    0x30492c061b0030,
    0x30492c061b0030,
    0x30492c061b0030,
    0x30492c061b0030,
    0x30492c061b0030,
    0x30492c061b0030,
    0x30492c061b0030,
    0x30492c061b0030,
    0x30492c061b0030,
    0x30492c061b0030,
    0x30492c061b0030,
    0x30c124861b0030,
    0x30c124861b0030,
    0x30c124861b0030,
    0x30c124861b0030,
    0x30c124861b0030,
    0x30c124861b0030,
    0x30c124861b0030,
    0x30c124861b0030,
    0x30c124861b0030,
    0x30c124861b0030,
    0x30c124861b0030,
    0x30c124861b0030,
    0x30c124861b0030,
    0x30c124861b0030,
    0x30c124861b0030,
    0x30c124861b0030,
    0x30c124b0186030,
    0x30c124b0186030,
    0x30c124b0186030,
    0x30c124b0186030,
    0x30c124b0186030,
    0x30c124b0186030,
    0x30c124b0186030,
    0x30c124b0186030,
    0x30c124b0186030,
    0x30c124b0186030,
    0x30c124b0186030,
    0x30c124b0186030,
    0x30c124b0186030,
    0x30c124b0186030,
    0x30c124b0186030,
    0x30c124b0186030,
    0x30c124b0186030,
    0x30c124b0186030,
    0x30c124b0186030,
    0x30c124b0186030,
    0x30c124b0186030,
    0x30c124b0186030,
    0x30c124b0186030,
    0x30c124b0186030,
    0x30c124b0186030,
    0x30c124b0186030,
    0x30c124b0186030,
    0x30c124b0186030,
    0x30c124b0186030,
    0x30c124b0186030,
    0x30c124b0186030,
    0x30c124b0186030,
    0x30c30c30c30c30,
    0x30c30c30c30c30,
    0x30c30c30c30c06,
    0x30c30c30c30c06,
    0x30c30c30c30c06,
    0x30c30c30c30c06,
    0x30c30c30c30c06,
    0x30c30c30c30c06,
    0x30c30c30c30c06,
    0x30c30c30c30c06,
    0x30c30c30c30c06,
    0x30c30c30c30c06,
    0x30c30c30c30c06,
    0x30c30c30c30c06,
    0x30c30c30c30c06,
    0x30c30c30c30c06,
    0x30c30c30c30c06,
    0x30c30c30c30c06,
    0x30c30c30c30c06,
    0x30c30c30c30c06,
    0x30c30c30c30c06,
    0x30c30c30c30c06,
    0x30c30c30c30c06,
    0x30c30c30c30c06,
    0x30c30c30c30c06,
    0x30c30c30c30c06,
    0x30c30c30c30c06,
    0x30c30c30c30c06,
    0x30c30c30c30c06,
    0x30c30c30c30c06,
    0x30c30c30c30c06,
    0x30c30c30c30c06,
    0x30c30c30c30c0c,
    0x30c30c30c30c12,
    0x30c30c30c30c12,
    0x30c30c30c30c12,
    0x30c30c30c30c12,
    0x30c30c30c30c12,
    0x30c30c30c30c12,
    0x30c30c30c30c12,
    0x30c30c30c30c12,
    0x30c30c30c30c12,
    0x30c30c30c30c12,
    0x30c30c30c30c12,
    0x30c30c30c30c12,
    0x30c30c30c30c18,
    0x30c30c30c30c12,
    0x30c30c30c30c12,
    0x30c30c30c30c1e,
    0x30c30c30c30c24,
    0x30c30c30c30c24,
    0x30c30c30c30c24,
    0x30c30c30c30c2a,
    0x30c30c30c30c30,
    0x30c30c30c30c30,
    0x30c30c30c30c30,
    0x30c30c30c30c30,
    0x30c30c30c30c30,
    0x30c30c30c30c30,
    0x30c30c30c30c30,
    0x30c30c30c30c30,
    0x30c30c30c30c30,
    0x30c30c30c30c30,
    0x30c30c30c30c30,
];

/// shift-based dfa
#[unsafe(no_mangle)]
pub fn check_utf8_shift(data: &[u8]) -> bool {
    let mut state = 0;
    for byte in data {
        state = S_LUT[usize::from(*byte)] >> (state % 64);
    }
    return (state % 64) == 0;
}

/// chunked shift-based dfa
#[unsafe(no_mangle)]
pub fn check_utf8_shift_chunked(mut data: &[u8]) -> bool {
    while data.len() >= 8
        && u64::from_le_bytes(*data[..8].as_array().unwrap()) & 0x8080808080808080 == 0
    {
        data = &data[8..];
    }
    while data.len() > 32 {
        let chunk_len = if (data[32] & 0xc0) != 0x80 {
            32
        } else if (data[31] & 0xc0) != 0x80 {
            31
        } else if (data[30] & 0xc0) != 0x80 {
            30
        } else if (data[29] & 0xc0) != 0x80 {
            29
        } else {
            return false;
        };
        if !check_utf8_shift(&data[..chunk_len]) {
            return false;
        }
        data = &data[chunk_len..];
    }
    check_utf8_shift(data)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ByteClass {
    Ascii,
    Two,
    Three1,
    Three2,
    Three3,
    Four1,
    Four2,
    Four3,
    Cont1,
    Cont2,
    Cont3,
    Illegal,
}
pub static BYTE_CLASS_VARIANTS: [ByteClass; 12] = [
    ByteClass::Ascii,
    ByteClass::Two,
    ByteClass::Three1,
    ByteClass::Three2,
    ByteClass::Three3,
    ByteClass::Four1,
    ByteClass::Four2,
    ByteClass::Four3,
    ByteClass::Cont1,
    ByteClass::Cont2,
    ByteClass::Cont3,
    ByteClass::Illegal,
];

impl ByteClass {
    pub const fn from(value: u8) -> Self {
        use ByteClass::*;

        match value {
            0x00..=0x7f => Ascii,
            0x80..=0x8f => Cont1,
            0x90..=0x9f => Cont2,
            0xa0..=0xbf => Cont3,
            0xc0..=0xc1 => Illegal,
            0xc2..=0xdf => Two,
            0xe0..=0xe0 => Three1,
            0xe1..=0xec => Three2,
            0xed..=0xed => Three3,
            0xee..=0xef => Three2,
            0xf0..=0xf0 => Four1,
            0xf1..=0xf3 => Four2,
            0xf4..=0xf4 => Four3,
            0xf5..=0xff => Illegal,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ForwardDfa {
    Ok,     // bytes scanned so far are valid UTF-8
    One,    // need one continuation byte
    Two1,   // avoid overlong
    Two2,   // any two continuation bytes
    Two3,   // avoid surrogates
    Three1, // avoid overlong
    Three2, // any three continuation bytes
    Three3, // avoid overlarge
    Fail,
}
pub static FORWARD_DFA_VARIANTS: [ForwardDfa; 9] = [
    ForwardDfa::Ok,
    ForwardDfa::One,
    ForwardDfa::Two1,
    ForwardDfa::Two2,
    ForwardDfa::Two3,
    ForwardDfa::Three1,
    ForwardDfa::Three2,
    ForwardDfa::Three3,
    ForwardDfa::Fail,
];

const fn dfa_offset(state: ForwardDfa) -> i32 {
    match state {
        ForwardDfa::Ok => 0,
        ForwardDfa::One => 24,
        ForwardDfa::Two1 => 5,
        ForwardDfa::Two2 => 27,
        ForwardDfa::Two3 => 10,
        ForwardDfa::Three1 => 13,
        ForwardDfa::Three2 => 19,
        ForwardDfa::Three3 => 16,
        ForwardDfa::Fail => 31,
    }
}

pub const fn dfa_ror_offset(state: ForwardDfa) -> u32 {
    match state {
        ForwardDfa::Ok => 8,
        ForwardDfa::One => 2,
        ForwardDfa::Two1 => 22,
        ForwardDfa::Two2 => 4,
        ForwardDfa::Two3 => 30,
        ForwardDfa::Three1 => 14,
        ForwardDfa::Three2 => 26,
        ForwardDfa::Three3 => 18,
        ForwardDfa::Fail => 0,
        // ForwardDfa::Ok => 8,
        // ForwardDfa::One => 2,
        // ForwardDfa::Two1 => 22,
        // ForwardDfa::Two2 => 4,
        // ForwardDfa::Two3 => 30,
        // ForwardDfa::Three1 => 14,
        // ForwardDfa::Three2 => 26,
        // ForwardDfa::Three3 => 18,
        // ForwardDfa::Fail => 0,
    }
}

const fn transitions(byte: ByteClass) -> i32 {
    let mut transitions = 0;
    let mut i = 0;
    while i < FORWARD_DFA_VARIANTS.len() {
        let state = FORWARD_DFA_VARIANTS[i];
        transitions |= dfa_offset(state.transition(byte)) << dfa_offset(state);
        i += 1;
    }
    let mut i = 0;
    while i < FORWARD_DFA_VARIANTS.len() {
        let state = FORWARD_DFA_VARIANTS[i];
        assert!(((transitions >> dfa_offset(state)) & 0x1f) == dfa_offset(state.transition(byte)));
        i += 1;
    }
    transitions
}

pub const fn ror_transitions(byte: ByteClass) -> u32 {
    let mut transitions = 0;
    let mut i = 0;
    while i < FORWARD_DFA_VARIANTS.len() {
        let state = FORWARD_DFA_VARIANTS[i];
        transitions |= dfa_ror_offset(state.transition(byte)).rotate_left(dfa_ror_offset(state));
        i += 1;
    }
    let mut i = 0;
    while i < FORWARD_DFA_VARIANTS.len() {
        let state = FORWARD_DFA_VARIANTS[i];
        assert!(
            (transitions.rotate_right(dfa_ror_offset(state)) & 0x1f)
                == dfa_ror_offset(state.transition(byte))
        );
        i += 1;
    }
    transitions
}

impl ForwardDfa {
    pub const fn transition(self, character: ByteClass) -> Self {
        match self {
            ForwardDfa::Ok => match character {
                ByteClass::Ascii => ForwardDfa::Ok,
                ByteClass::Two => ForwardDfa::One,
                ByteClass::Three1 => ForwardDfa::Two1,
                ByteClass::Three2 => ForwardDfa::Two2,
                ByteClass::Three3 => ForwardDfa::Two3,
                ByteClass::Four1 => ForwardDfa::Three1,
                ByteClass::Four2 => ForwardDfa::Three2,
                ByteClass::Four3 => ForwardDfa::Three3,
                _ => ForwardDfa::Fail,
            },
            ForwardDfa::One => match character {
                ByteClass::Cont1 => ForwardDfa::Ok,
                ByteClass::Cont2 => ForwardDfa::Ok,
                ByteClass::Cont3 => ForwardDfa::Ok,
                _ => ForwardDfa::Fail,
            },
            ForwardDfa::Two1 => match character {
                ByteClass::Cont3 => ForwardDfa::One,
                _ => ForwardDfa::Fail,
            },
            ForwardDfa::Two2 => match character {
                ByteClass::Cont1 => ForwardDfa::One,
                ByteClass::Cont2 => ForwardDfa::One,
                ByteClass::Cont3 => ForwardDfa::One,
                _ => ForwardDfa::Fail,
            },
            ForwardDfa::Two3 => match character {
                ByteClass::Cont1 => ForwardDfa::One,
                ByteClass::Cont2 => ForwardDfa::One,
                _ => ForwardDfa::Fail,
            },
            ForwardDfa::Three1 => match character {
                ByteClass::Cont2 => ForwardDfa::Two2,
                ByteClass::Cont3 => ForwardDfa::Two2,
                _ => ForwardDfa::Fail,
            },
            ForwardDfa::Three2 => match character {
                ByteClass::Cont1 => ForwardDfa::Two2,
                ByteClass::Cont2 => ForwardDfa::Two2,
                ByteClass::Cont3 => ForwardDfa::Two2,
                _ => ForwardDfa::Fail,
            },
            ForwardDfa::Three3 => match character {
                ByteClass::Cont1 => ForwardDfa::Two2,
                _ => ForwardDfa::Fail,
            },
            ForwardDfa::Fail => ForwardDfa::Fail,
        }
    }
}

/// LUT which maps byte to their class. Only use for bytes >= 128, all bytes < 128 are class 0 (ASCII)
pub static CLASS_LUT: [u8; 256] = const {
    let mut lut = [0; 256];
    let mut i = 0;
    while i < lut.len() {
        lut[i] = ByteClass::from(i as u8) as u8;
        i += 1;
    }
    lut
};

/// LUT for
pub static ROR_CLASS_LUT: [u32; 16] = const {
    let mut lut = [0; 16];
    let mut i = 0;
    while i < BYTE_CLASS_VARIANTS.len() {
        lut[i] = ror_transitions(BYTE_CLASS_VARIANTS[i]);
        i += 1;
    }
    lut
};

/// LUT for SRA-based UTF8 validator
pub static SRA_LUT: [i32; 256] = const {
    let mut lut = [0; 256];
    let mut i = 0;
    while i < lut.len() {
        lut[i] = transitions(ByteClass::from(i as u8));
        i += 1;
    }
    lut
};

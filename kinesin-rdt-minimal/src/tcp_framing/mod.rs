//! TCP frame layer

macro_rules! frames_to_enum {
    ($name:ident; $($variants:ident),*) => {
        pub enum $name {
            $(
                $variants(::kinesin_rdt::frame::$variants)
            ),*
        }

        impl $name {
            pub fn type_erase(&mut self) -> &mut dyn ::kinesin_rdt::frame::SerializeToEnd {
                match self {
                    $(
                        Self::$variants(ref mut f) => f
                    ),*
                }
            }
        }
    }
}

frames_to_enum! {
    MacroFrame;
    StreamData, StreamWindowLimit, StreamFinal
}

pub fn yay(mut frame: MacroFrame, buf: &mut [u8]) {
    frame.type_erase().write(buf);
}

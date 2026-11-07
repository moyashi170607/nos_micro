#![no_std]
#![no_main]

use core::panic::PanicInfo;

// エントリポイントは HAL / ランタイム（embassy-rp など）を追加するときに定義する

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}

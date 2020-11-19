pub fn setup() {
    clamav_rs::initialize().expect("initialize to succeed");
}

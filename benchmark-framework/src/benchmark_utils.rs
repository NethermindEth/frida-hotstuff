use common::data::FriData;
use rand_core::{OsRng, RngCore};

pub fn generate_test_data(height: usize, width: usize) -> FriData {
    //  let flattened_data: Vec<u8> = fri_data.clone().into();
    let mut flattened_data: Vec<u8> = Vec::with_capacity(height * width);

    let mut rng = OsRng;
    for _ in 0..(height * width) {
        let mut bytes = [0u8; 1];
        rng.fill_bytes(&mut bytes);
        flattened_data.push(bytes[0]);
    }

    let mut fri_data: FriData = FriData::new(height, width);
    fri_data.reconstruct_data_list(&flattened_data);
    fri_data
}

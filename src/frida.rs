use bytes::Bytes;

#[derive(Debug)]
pub struct FriData {
    pub data_list: Vec<Vec<u8>>,
}

pub const MAX_BLOB_SIZE: usize = 100 * 100;

pub fn arrange_blobs(merged_blob: &Bytes) -> FriData {
    // Using static arrangement for now:
    let (w, h) = (100, 100);

    // Dynamic approach that seems to give the shortest minimum commitment and proof size:
    // // Rectangle will have height h and width h*b, where b is the number of bytes in a field element.
    // // This leads to field element arrangement to be near-square.
    // let b = Element::ELEMENT_BYTES;
    // let h = (merged_blob.len() as f64 / b as f64).sqrt().ceil() as usize;
    // let w = h * b;

    assert!(merged_blob.len() <= MAX_BLOB_SIZE, "blob too large");
    assert!(merged_blob.len() <= h * w, "blob too large");

    let mut data_list = vec![Vec::with_capacity(w); h];
    let mut data_list_index_iter = (0..data_list.len()).cycle();
    for &byte in merged_blob.iter() {
        let index = data_list_index_iter.next().unwrap();
        data_list[index].push(byte);
    }

    FriData { data_list }
}
use bytes::Bytes;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FriData {
    pub data_list: Vec<Vec<u8>>,
    pub height: usize,
    pub width: usize,
    pub max_blob_size: usize,
}

// pub const MAX_BLOB_SIZE: usize = 100 * 100;

// pub const W: usize = 100;
// pub const H: usize = 100;

impl FriData {
    pub fn new(height: usize, width: usize) -> Self {
        Self {
            data_list: vec![],
            height,
            width,
            max_blob_size: height * width,
        }
    }

    pub fn arrange_blobs(&mut self, merged_blob: &Bytes) {
        // Using static arrangement for now:
        // let (w, h) = (100, 100);

        // Dynamic approach that seems to give the shortest minimum commitment and proof size:
        // // Rectangle will have height h and width h*b, where b is the number of bytes in a field element.
        // // This leads to field element arrangement to be near-square.
        // let b = Element::ELEMENT_BYTES;
        // let h = (merged_blob.len() as f64 / b as f64).sqrt().ceil() as usize;
        // let w = h * b;

        assert!(merged_blob.len() <= self.max_blob_size, "blob too large");
        assert!(
            merged_blob.len() <= self.height * self.width,
            "blob too large"
        );

        let mut data_list = vec![Vec::with_capacity(self.width); self.height];
        let mut data_list_index_iter = (0..data_list.len()).cycle();
        for &byte in merged_blob.iter() {
            let index = data_list_index_iter.next().unwrap();
            data_list[index].push(byte);
        }

        self.data_list = data_list;
    }

    pub fn reconstruct_data_list(&mut self, flattened_data: &[u8]) {
        let mut data_list = vec![Vec::with_capacity(self.width); self.height];

        for (i, &byte) in flattened_data.iter().enumerate() {
            let index = i % self.height;
            data_list[index].push(byte);
        }

        self.data_list = data_list;
    }
}

impl From<FriData> for Vec<u8> {
    fn from(fri_data: FriData) -> Self {
        fri_data
            .data_list
            .iter()
            .flat_map(|v| v.iter())
            .cloned()
            .collect()
    }
}

// impl From<Vec<u8>> for FriData {
//     fn from(&self, bytes: Vec<u8>) -> Self {
//         let data_list = self.reconstruct_data_list(&bytes);
//         FriData { data_list }
//     }
// }

// impl From<&Vec<u8>> for FriData {
//     fn from(bytes: &Vec<u8>) -> Self {
//         let data_list = reconstruct_data_list(bytes);
//         FriData { data_list }
//     }
// }

// pub fn reconstruct_data_list(flattened_data: &[u8]) -> Vec<Vec<u8>> {
//     let mut data_list = vec![Vec::with_capacity(W); H];

//     for (i, &byte) in flattened_data.iter().enumerate() {
//         let index = i % H;
//         data_list[index].push(byte);
//     }

//     data_list
// }

#[cfg(test)]
mod tests {
    use crate::blob_helper::{YodaBlobData, merge_blobs};

    use super::*;

    #[test]
    fn test_reconstruct_data_list() {
        let yoda_blob_data_1 = YodaBlobData::from_raw(Bytes::from_static(b"1234567890")).unwrap();
        let yoda_blob_data_2 = YodaBlobData::from_raw(Bytes::from_static(b"hello")).unwrap();
        let yoda_blob_data_3 = YodaBlobData::from_raw(Bytes::from_static(b"world")).unwrap();

        let merged_blob = merge_blobs(&[yoda_blob_data_1, yoda_blob_data_2, yoda_blob_data_3]);
        let mut fri_data = FriData::new(100, 100);
        fri_data.arrange_blobs(&merged_blob);
        let flattened_data: Vec<u8> = fri_data.clone().into();

        let mut back_to_fri_data = FriData::new(100, 100);
        back_to_fri_data.reconstruct_data_list(&flattened_data);
        assert_eq!(fri_data, back_to_fri_data);
    }
}

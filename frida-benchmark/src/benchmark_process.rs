use frida_poc::winterfell::FriOptions;

pub struct Benchmark<'a> {
    pub num_of_validators: &'a Vec<u32>,
    pub data_sizes: &'a Vec<(u32, u32)>,
    pub fri_options: &'a Vec<FriOptions>,
}

impl<'a> Benchmark<'a> {
    pub fn new(
        num_of_validators: &'a Vec<u32>,
        data_sizes: &'a Vec<(u32, u32)>,
        fri_options: &'a Vec<FriOptions>,
    ) -> Self {
        Self {
            num_of_validators,
            data_sizes,
            fri_options,
        }
    }

    pub fn start(&self) {
        for num_of_validator in self.num_of_validators {
            for data_size in self.data_sizes {
                for fri_option in self.fri_options {
                    // benchmarking logic here
                }
            }
        }
    }
}

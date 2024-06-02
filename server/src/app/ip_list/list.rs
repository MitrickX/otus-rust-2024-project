use super::ip::IP;

trait List {
    fn add(ip: IP) -> Result<(), Box<dyn std::error::Error>>;
    fn delete(ip: IP) -> Result<(), Box<dyn std::error::Error>>;
    fn is_conform(ip: IP) -> Result<bool, Box<dyn std::error::Error>>;
}

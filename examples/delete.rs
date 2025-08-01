use route_manager::{Route, RouteManager};

pub fn main() {
    // Need to set up the correct gateway
    let route = Route::new("192.168.2.0".parse().unwrap(), 24).with_if_index(1);
    println!("route delete {route:?}");
    let result = RouteManager::new().unwrap().delete(&route);
    println!("{result:?}");
}

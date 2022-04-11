use crate::Yay;

#[test]
fn it_works() {
    let yay = Yay { x: 1, y: 2 };
    assert_eq!(yay.x, 1);
    assert_eq!(yay.y, 2);
}

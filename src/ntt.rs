use crate::params::{N, Q, Q_INV};

// Precomputed tables for NTT
const ZETAS: [i16; 128] = [
    -1044, -758, -359, -1517, 1493, 1422, 287, 202, -171, 622, 1577, 182, 962,
    -250, 1120, -1164, -1182, -1530, -1278, 794, -1510, -854, -870, 478, -1036,
    -658, -23, -1238, -1255, -430, -555, 1222, 1632, -122, -265, -1549, -143,
    -1698, -1321, -1158, -1333, -731, -1141, -1590, 816, -114, -1343, -1289,
    -1563, -338, -1163, -1176, -1619, -1110, 298, -1274, -1428, -884, -1421,
    -1304, -496, -1607, -1527, -918, 1199, -1067, -1263, -310, -1692, -1218,
    -1299, -1254, -1474, 446, -1445, -1398, -1345, 1223, 1479, -1021, 619,
    -149, -1499, -1324, 401, -1208, -78, -561, -1580, -1384, -26, -1653, -219,
    -1432, 1424, -1139, -1466, -1353, -1043, 1505, -785, -1292, -1472,
    -1318, -1363, -1423, -1342, 1481, -1451, 1069, -1532, -1103, -1375, -28,
    -1272, -113, -1503, -1393, -1172, 1494, -1579, -586, -1341, -1469, -1628,
    -1242, -1491, -1455,
];

// NTT forward transformation
pub fn ntt(p: &mut [i16; N]) {
    let mut k = 1;
    let mut len = 128;
    while len >= 2 {
        let mut start = 0;
        while start < N {
            let zeta = ZETAS[k];
            k += 1;
            for j in start..start + len {
                let t = (zeta as i32 * p[j + len] as i32) % Q as i32;
                p[j + len] = (p[j] as i32 - t + Q as i32) as i16 % Q as i16;
                p[j] = (p[j] as i32 + t) as i16 % Q as i16;
            }
            start += 2 * len;
        }
        len >>= 1;
    }
}

// NTT inverse transformation
pub fn inv_ntt(p: &mut [i16; N]) {
    let mut k = 127;
    let mut len = 2;
    while len <= 128 {
        let mut start = 0;
        while start < N {
            let zeta = ZETAS[k];
            k -= 1;
            for j in start..start + len {
                let t = p[j];
                p[j] = (t + p[j + len]) % Q as i16;
                p[j + len] = (t - p[j + len] + Q as i16) % Q as i16;
                p[j + len] = ((zeta as i32 * p[j + len] as i32) % Q as i32) as i16;
            }
            start += 2 * len;
        }
        len <<= 1;
    }

    for i in 0..N {
        p[i] = ((p[i] as i32 * Q_INV as i32) % Q as i32) as i16;
    }
}

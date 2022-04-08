// The MIT License (MIT)
// Copyright © 2021 Aukbit Ltd.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
#![allow(dead_code)]
pub fn mean(list: &Vec<f64>) -> f64 {
    if list.len() == 0 {
        return 0.0;
    }
    let sum: f64 = list.iter().sum();
    sum / (list.len() as f64)
}

pub fn standard_deviation(list: &Vec<f64>) -> f64 {
    let m = mean(list);
    let mut variance: Vec<f64> = list.iter().map(|&score| (score - m).powf(2.0)).collect();
    mean(&mut variance).sqrt()
}

pub fn median(list: &mut Vec<u32>) -> u32 {
    if list.len() == 0 {
        return 0;
    }
    list.sort();
    let mid = list.len() / 2;
    list[mid]
}

// Calculate 90% confidence interval
pub fn confidence_interval_90(list: &Vec<f64>) -> (f64, f64) {
    confidence_interval(list, 1.645)
}

// Calculate 95% confidence interval
pub fn confidence_interval_95(list: &Vec<f64>) -> (f64, f64) {
    confidence_interval(list, 1.96)
}

// Calculate 99% confidence interval
pub fn confidence_interval_99(list: &Vec<f64>) -> (f64, f64) {
    confidence_interval(list, 2.576)
}

// Calculate 99.9% confidence interval
pub fn confidence_interval_99_9(list: &Vec<f64>) -> (f64, f64) {
    confidence_interval(list, 3.291)
}

// https://www.mathsisfun.com/data/confidence-interval.html
pub fn confidence_interval(list: &Vec<f64>, z: f64) -> (f64, f64) {
    let m = mean(list);
    let sd = standard_deviation(list);
    let v = z * (sd / ((list.len() as f64).sqrt()));
    (m - v, m + v)
}
// Find outliers by Interquartile Range(IQR)
// https://www.statisticshowto.com/statistics-basics/find-outliers/
pub fn iqr_interval(list: &mut Vec<u32>) -> (f64, f64) {
    if list.len() == 0 {
        return (0.0, 0.0);
    }
    list.sort();
    let q1 = median(&mut (&list[..&list.len() / 2]).into());
    let q3 = median(&mut (&list[&list.len() - (&list.len() / 2)..]).into());
    let iqr = q3 - q1;
    (
        (q1 as f64) - (iqr as f64 * 1.5),
        (q3 as f64) + (iqr as f64 * 1.5),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn calculate_mean() {
        let v = vec![1.0, 2.0, 3.0, 4.0, 5.0, 4.0, 2.0, 6.0];
        assert_eq!(mean(&v), 3.375);
    }

    #[test]
    fn calculate_median() {
        let mut v = vec![1, 2, 3, 4, 5, 6, 7, 8, 9];
        assert_eq!(median(&mut v), 5);
    }

    #[test]
    fn calculate_confidence_interval_99_9() {
        let v = vec![1.0, 2.0, 3.0, 4.0, 5.0, 4.0, 2.0, 6.0];
        assert_eq!(
            confidence_interval_99_9(&v),
            (1.5410332231275632, 5.208966776872437)
        );
    }

    #[test]
    fn calculate_iqr_interval() {
        let mut v = vec![1, 2, 3, 4, 5, 4, 2, 6, 3];
        assert_eq!(iqr_interval(&mut v), (-2.5, 9.5));
    }

    #[test]
    fn identify_outliers() {
        fn to_u32_vec(v: Vec<f64>) -> Vec<u32> {
            let out: Vec<u32> = v.iter().map(|a| *a as u32).collect();
            out
        }
        // Testing outliers in Val. Groups
        let v = vec![1260.0, 1240.0, 1220.0, 1000.0, 700.0];
        assert_eq!(
            confidence_interval_99_9(&v),
            (769.4933332395003, 1398.5066667604997)
        );
        assert_eq!(
            confidence_interval_99(&v),
            (837.8227974551664, 1330.1772025448336)
        );
        assert_eq!(
            confidence_interval_95(&v),
            (896.6912589332788, 1271.3087410667213)
        );
        assert_eq!(iqr_interval(&mut to_u32_vec(v)), (610.0, 1650.0));

        let v = vec![1480.0, 1460.0, 1380.0, 640.0, 580.0];
        assert_eq!(
            confidence_interval_99_9(&v),
            (506.8792331492781, 1709.1207668507218)
        );
        // confidence_interval_99 -> catched 700
        assert_eq!(
            confidence_interval_99(&v),
            (637.4782450904103, 1578.5217549095896)
        );
        assert_eq!(
            confidence_interval_95(&v),
            (749.9943169166165, 1466.0056830833835)
        );
        assert_eq!(iqr_interval(&mut to_u32_vec(v)), (-620.0, 2740.0));

        let v = vec![2040.0, 1900.0, 1780.0, 1640.0, 1180.0];
        assert_eq!(
            confidence_interval_99_9(&v),
            (1273.5481109222794, 2142.4518890777204)
        );
        // confidence_interval_99 ok
        assert_eq!(
            confidence_interval_99(&v),
            (1367.936777191064, 2048.063222808936)
        );
        assert_eq!(
            confidence_interval_95(&v),
            (1449.25624351494, 1966.74375648506)
        );
        assert_eq!(iqr_interval(&mut to_u32_vec(v)), (1040.0, 2640.0));

        let v = vec![1840.0, 1820.0, 1660.0, 1260.0, 1060.0];
        assert_eq!(
            confidence_interval_99_9(&v),
            (1066.8464598735038, 1989.1535401264962)
        );
        assert_eq!(
            confidence_interval_99(&v),
            (1167.0363052671364, 1888.9636947328636)
        );
        assert_eq!(
            confidence_interval_95(&v),
            (1253.3537105293428, 1802.6462894706572)
        );
        assert_eq!(iqr_interval(&mut to_u32_vec(v)), (390.0, 2710.0));

        let v = vec![2340.0, 2340.0, 2280.0, 1280.0, 400.0];
        assert_eq!(
            confidence_interval_99_9(&v),
            (584.5340107816064, 2871.4659892183936)
        );
        assert_eq!(
            confidence_interval_99(&v),
            (832.9625073756966, 2623.0374926243035)
        );
        assert_eq!(
            confidence_interval_95(&v),
            (1046.9932121336824, 2409.0067878663176)
        );
        assert_eq!(iqr_interval(&mut to_u32_vec(v)), (-310.0, 3930.0));

        let v = vec![2140.0, 2140.0, 2040.0, 1460.0, 740.0];
        assert_eq!(
            confidence_interval_99_9(&v),
            (902.7459132704533, 2505.2540867295465)
        );
        assert_eq!(
            confidence_interval_99(&v),
            (1076.8257285277082, 2331.174271472292)
        );
        assert_eq!(
            confidence_interval_95(&v),
            (1226.8021847493433, 2181.1978152506567)
        );
        assert_eq!(iqr_interval(&mut to_u32_vec(v)), (440.0, 3160.0));

        let v = vec![2140.0, 2140.0, 2040.0, 2460.0, 2240.0];
        assert_eq!(
            confidence_interval_99(&v),
            (2039.5228538768988, 2368.477146123101)
        );
        let v = vec![2440.0, 2420.0, 2320.0, 1620.0, 1560.0];
        assert_eq!(
            confidence_interval_99(&v),
            (1615.6828490411522, 2528.317150958848)
        );
        assert_eq!(iqr_interval(&mut to_u32_vec(v)), (390.0, 3670.0));
        let v = vec![2360.0, 2360.0, 2280.0, 2220.0, 2160.0];
        assert_eq!(
            confidence_interval_99(&v),
            (2185.700268279468, 2366.299731720532)
        );
        let mut v = vec![
            2720, 2700, 2580, 2420, 1920, 2500, 2460, 2420, 2420, 2100, 2700, 2700, 2700, 1860,
            1580, 2360, 2360, 2280, 2220, 2160, 2380, 2280, 2240, 2140, 2120, 2560, 2540, 2400,
            1820, 1700, 3040, 3000, 2980, 1460, 500, 2520, 2520, 2460, 2220, 1120, 2280, 2260,
            2180, 2140, 1720, 2240, 2180, 2040, 2020, 1980, 2280, 2240, 2140, 1940, 1860, 2440,
            2420, 2320, 1620, 1560, 2440, 2420, 2420, 2300, 720, 2220, 2160, 2160, 1820, 1480,
            2560, 2520, 2520, 1140, 940, 2200, 2180, 2100, 1600, 1560, 2280, 2040, 1980, 1680,
            1640, 2140, 2140, 2080, 1900, 1320, 1900, 1900, 1900, 1860, 1580, 2060, 1980, 1960,
            1540, 1540, 1920, 1840, 1800, 1800, 1700, 2080, 2060, 2020, 1980, 640, 2020, 2000,
            1840, 1760, 780, 1900, 1860, 1840, 1380, 1360, 1960, 1820, 1760, 1660, 1040, 2040,
            2040, 1920, 1760, 200, 1920, 1900, 1880, 1240, 980, 1920, 1920, 1920, 1680, 80, 1740,
            1740, 1700, 1200, 940, 1720, 1720, 1680, 1660, 460, 1640, 1540, 1440, 1340, 1000, 1860,
            1800, 1700, 940, 660, 1580, 1520, 1440, 1340, 760, 1360, 1320, 1280, 1220, 1160, 1460,
            1440, 1440, 1320, 640, 1240, 1180, 1160, 720, 200, 1040, 960, 880, 860, 720, 660, 660,
            600, 120, 40, 460, 440, 360, 320, 20, 20, 20, 0, 0,
        ];
        fn to_f64_vec(v: Vec<u32>) -> Vec<f64> {
            let out: Vec<f64> = v.iter().map(|a| *a as f64).collect();
            out
        }
        assert_eq!(
            confidence_interval_99(&to_f64_vec(v.clone())),
            (1567.4800918747533, 1815.0324709393171)
        );
        assert_eq!(
            confidence_interval_99_9(&to_f64_vec(v.clone())),
            (1533.1245113174623, 1849.388051496608)
        );
        assert_eq!(iqr_interval(&mut v), (60.0, 3420.0));
    }
}

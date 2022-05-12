# Report legends

By typing `!legends` in one of the main public channels the following message will be shown:

## 💡 Stats are collected between the interval of blocks specified in each report.

### _Val. performance report legend:_

`!subscribe STASH_ADDRESS`

↻: Total number of core assignments (parachains) by the validator.  
❒: Total number of authored blocks by the validator.  
✓i: Total number of implicit votes by the validator.
✓e: Total number of explicit votes by the validator.  
✗: Total number of missed votes by the validator.  
MVR: Missed Votes Ratio (MVR) `MVR = (✗) / (✓i + ✓e + ✗)`.  

GRD: Grade reflects the Backing Votes Ratio (BVR) `BVR = 1 - MVR` by the validator:  
‣ A+ = BVR > 99%  
‣ A  = BVR > 95%  
‣ B+ = BVR > 90%  
‣ B  = BVR > 80%  
‣ C+ = BVR > 70%  
‣ C  = BVR > 60%  
‣ D+ = BVR > 50%  
‣ D  = BVR > 40%  
‣ F  = BVR <= 40%  

PPTS: Sum of para-validator points the validator earned.  
TPTS: Sum of para-validator points + authored blocks points the validator earned.  
*: ✓ is the Total number of (implicit + explicit) votes and ✗ is the Total number of missed votes by the subscribed validator.  
A, B, C, D: Represents each validator in the same val. group as the subscribed validator.

### _Val. groups performance report legend:_

`!subscribe groups`

↻: Total number of core assignements.  
❒: Total number of authored blocks.  
✓i: Total number of implicit votes.  
✓e: Total number of explicit votes.  
✗: Total number of missed votes by the validator.  
GRD: Grade reflects the Backing Votes Ratio.  
MVR: Missed Votes Ratio.  
PPTS: Sum of para-validator points the validator earned.  
TPTS: Sum of para-validator points + authored blocks points the validator earned.  
_Note: Val. groups and validators are sorted by para-validator points in descending order._

### _Parachains performance report legend:_

`!subscribe parachains`

↻: Total number of validator group rotations per parachain.  
❒: Total number of authored blocks from all validators when assigned to the parachain.  
✓i: Total number of implicit votes from all validators when assigned to the parachain.  
✓e: Total number of explicit votes from all validators when assigned to the parachain.  
✗: Total number of missed votes from all validators when assigned to the parachain.  
PPTS: Sum of para-validator points from all validators.  
TPTS: Sum of para-validator points + authored blocks points from all validators.  
_Note: Parachains are sorted by para-validator points in descending order._

### _Validators performance insights report legend:_

`!subscribe insights`

Score: `score = (1 - mvr) * 0.75 + ((avg_pts - min_avg_pts) / (max_avg_pts - min_avg_pts)) * 0.15 + (pv_sessions / total_sessions) * 0.1`

Timeline: Graphic performance representation in the last X sessions:  
‣ ❚ = BVR >= 90%  
‣ ❙ = BVR >= 60%  
‣ ❘ = BVR >= 40%  
‣ ! = BVR >= 20%  
‣ ¿ = BVR < 20%  
‣ ? = No-votes  
‣ • = Not P/V  
‣ _ = Waiting  

_Note: This report also provides all the validator info described before._

# Report legends

By typing `!legends` in one of the main public channels the following message will be shown:

## 💡 Stats are collected between the interval of blocks specified in each report.

### _Val. performance report legend:_

`!subscribe STASH_ADDRESS`

↻: Total number of core assignments (parachains) by the validator.  
❒: Total number of authored blocks by the validator.  
✓i: Total number of implicit votes by the validator.
✓e: Total number of explicit votes by the validator.  
✗v: Total number of missed votes by the validator.
✓b: Total number of blocks containing populated bitfields from the validator.
✗b: Total number of blocks with bitfields unavailable or empty from the validator.
MVR: Missed Votes Ratio (MVR) `MVR = (✗) / (✓i + ✓e + ✗)`.
BAR: Bitfields Availability Ratio `(BAR = (✓b) / (✓b + ✗b))`.

GRD: Grade is calculated as 75% of the Backing Votes Ratio (BVR = 1-MVR) combined with 25% of the Bitfields Availability Ratio (BAR) by one or more validators `(RATIO = BVR*0.75 + BAR*0.25)`:
‣ A+ = RATIO > 99%
‣ A  = RATIO > 95%
‣ B+ = RATIO > 90%
‣ B  = RATIO > 80%
‣ C+ = RATIO > 70%
‣ C  = RATIO > 60%
‣ D+ = RATIO > 50%
‣ D  = RATIO > 40%
‣ F  = RATIO <= 40%

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
✗v: Total number of missed votes by the validator.
✓b: Total number of blocks containing populated bitfields from the validator.
✗b: Total number of blocks with bitfields unavailable or empty from the validator.
GRD: Grade reflects the Backing Votes Ratio.  
MVR: Missed Votes Ratio.
BAR: Bitfields Availability Ratio.
PPTS: Sum of para-validator points the validator earned.  
TPTS: Sum of para-validator points + authored blocks points the validator earned.  
_Note: Val. groups and validators are sorted by para-validator points in descending order._

### _Parachains performance report legend:_

`!subscribe parachains`

↻: Total number of validator group rotations per parachain.  
❒: Total number of authored blocks from all validators when assigned to the parachain.  
✓i: Total number of implicit votes from all validators when assigned to the parachain.  
✓e: Total number of explicit votes from all validators when assigned to the parachain.  
✗v: Total number of missed votes from all validators when assigned to the parachain.  
PPTS: Sum of para-validator points from all validators.  
TPTS: Sum of para-validator points + authored blocks points from all validators.  
_Note: Parachains are sorted by para-validator points in descending order._

### _Validators performance insights report legend:_

`!subscribe insights`

Score: `score = (1 - mvr) * 0.55 + bar * 0.25 + ((avg_pts - min_avg_pts) / (max_avg_pts - min_avg_pts)) * 0.18 + (pv_sessions / total_sessions) * 0.07`  
Commission Score: `commission_score = score * 0.25 + (1 - commission) * 0.75`  

Timeline: Graphic performance representation in the last X sessions:  
‣ ❚ = RATIO >= 90%  
‣ ❙ = RATIO >= 60%  
‣ ❘ = RATIO >= 40%  
‣ ! = RATIO >= 20%  
‣ ¿ = RATIO < 20%  
‣ ? = No-show  
‣ • = Not P/V  
‣ _ = Waiting  

_Note: This report also provides all the validator info described before._

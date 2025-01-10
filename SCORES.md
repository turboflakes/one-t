# ONE-T scores

## Performance Score

`performance_score = (1 - mvr) * 0.50 + bar * 0.25 + ((avg_pts - min_avg_pts) / (max_avg_pts - min_avg_pts)) * 0.18 + (pv_sessions / total_sessions) * 0.07`  

## Commission Score

`commission_score = performance_score * 0.25 + (1 - commission) * 0.75`
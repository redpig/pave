# Long-horizon economics of pro-rata cumulative shares (no gating, no cap):
# Attacker places F fake orders at t=0 with weight w (relative to later 1.0).
# Each period: honest volume v_t = v0*(1+g)^t, pool_t = p*v_t, distributed pro rata over cumulative shares.
# Fake order cost = Cost+Surplus. Analytic: lifetime payout per fake ~ p*w*ln(C_T/C_0).
import math
p, cost = 1.0, 4.0   # PoolShare, Cost+Surplus
def run(w, g, T, v0=10.0, F=1):
    S_att = F*w; C = S_att + 0.0; got = 0.0; v = v0
    for t in range(T):
        C += v                  # honest shares (weight 1)
        pool = p*(v + (F if t==0 else 0))
        got += pool * S_att / C
        v *= (1+g)
    return got/F, C/(F*w + v0)
for w in [1.0, 1.5, 4.0]:
    for g,T in [(0.0,60),(0.05,60),(0.05,120),(0.10,120)]:
        per, growth = run(w,g,T)
        print(f"w={w:<4} g={g:<5} T={T:<4} payout/fake={per:6.2f}  cost={cost}  profit={per-cost:+6.2f}  "
              f"C growth x{growth:9.1f}  p*w*ln(growth)={p*w*math.log(growth):6.2f}")

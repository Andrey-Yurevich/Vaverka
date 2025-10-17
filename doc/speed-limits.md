# Rate limit demystification

Vaverka supports rate limiting to help avoid network congestion and other issues. You can set a maximum number of packets per second (pps) with:
```shell
vaverka –-pps <value>
```
- **Minimum value:** 64
- **Default value:** 4,096
- **Scope:** Global (applies to the entire instance and is distributed among all scan rules)

Below is more detail:

1. The `pps` value sets the upper limit. If your NIC or CPU cannot reach that rate, scanning runs as fast as possible.
2. The actual maximum PPS is the user-defined value **plus** a burst of 256. For example, if you set `--pps 64`, the real maximum becomes `64 + 256`.
    - This is due to the token bucket rate-limiting algorithm requiring a burst value. A fixed burst of 256 simplifies implementation.
3. Vaverka sends packets in chunks of 64. If your `pps` is not evenly divisible by 64, it gets rounded down, then 256 is added as burst. Here’s a summary:

| Specified PPS | Actual PPS | Maximum PPS | Explanation                                                |
|---------------|------------|-------------|------------------------------------------------------------|
| 2,000,000     | 2,000,000  | 2,000,256   | Evenly divisible by 64, plus 256 burst.                    |
| 20,000        | 19,968     | 20,224      | 20,000 // 64 = 312, 312 × 64 = 19,968; then +256 = 20,224. |
| 4,096         | 4,096      | 4,352       | Evenly divisible by 64, plus 256 burst.                    |

4. **Recommended Values:** Use high PPS only if you understand potential network impact. Modern systems can handle tens of thousands of PPS or even hundreds of thousands. (TODO: Add recommended AWS values.)

> **Disclaimer:** Even if your network can handle millions of packets per second, adding Vaverka traffic might be the final push that causes a network failure. Please use rate limits carefully.


<div align="center">
  <img src="https://media3.giphy.com/media/v1.Y2lkPTc5MGI3NjExaWE0cmpjeGx6eDJuaXd6bWFmdDc1bjZ2eDcwZTFxM2lmbjJ3NjBobSZlcD12MV9pbnRlcm5hbF9naWZfYnlfaWQmY3Q9Zw/3o6MbsY8iTKcxam4cU/giphy.gif" alt="boom">
</div>
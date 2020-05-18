read [this](https://cyber.wtf/2016/08/01/two-covert-channels/) this article

<h3>from Article</h3>

<h2>Sowing a seed too many – side channel with rdseed</h2>

“Under heavy load, with multiple cores executing RDSEED in parallel, it is possible for the demand of random numbers by software processes/threads to exceed the rate at which the random number generator hardware can supply them. This will lead to the RDSEED instruction returning no data transitorily.”

 

That sounds like a very obvious side channel indeed. The RDSEED instruction has been added with the Broadwell micro architecture and uses heat entropy in the CPU to generate cryptographically strong random number. The problem with this instruction seems that for enough entropy to build up a bit of time is needed between calls to RDSEED. Thus intel designed the instruction to return an “error” using the carry flag if insufficient time has passed since the last call of RDSEED. So the basic idea is that an attacker could create a covert channel using this instruction. To send a 1 bit the sender implant loops an rdseed instruction and mean while the receiver runs a loop spaced with plenty of time between rdseed. The information is extracted in the recievesr’s end from a count of failed rdseed instructions. My simple test setup was an infinite sender loop which either called the rdseed instruction or not depending on the bit I wanted to send. My receiver looped 1000 times around did an rdseed instruction followed by a  10 ms Sleep() call.  0 bits caused zero failures in the receiver loop and typically around 800 failures in the 1bit scenario.  I tested only on a I3-5005U Broadwell laptop, but with the sender and receiver thread pinned on same core as well as on different cores. Results where near identical.

# Challenge Name
Zahard Welcome

## My solve
**Flag:** `citadel{7h3_c174d3l_b3ck0n5}`

It told us to visit the place everywhere gathers so I first checked into the general section of the official discord server but in the meanwhile my teammate checked for other sections eventually we got the flag simply pasted in `Rules` Section of Discord.

## What I learned
Basic Searching Through Discord

## References 
None



# Challenge Name
Omniscent Metadata

## My solve
**Flag:** `citadel{th1s_ch4ll3ng3_1s_f0r_th4t_0n3_ex1ft00l_4nd_b1nw4lk_enthus14st}`

1. I firstly went to a metadata extracter website and took out teh metadata inside the metadata it was written "kdj has the habit of hiding image inside an image".
2. I first thought this can be a steganography question just like the one in ChildrenOfNite challenge so I ran the command `steghide extract -sf challenge.jpg` but to run such commands you need to know the paraphase which I didn't in this case.
3. Since I wasn't sure what to do next I searched `How to find a image inside an image` there I found a video by ctf school on binwalker and next I used binwalker to finally get the flag.
Note: After reading the official Write-up I understood that this exercise was very easy and I just had to use `foremost`

## What I learned
How to use Binwalker

## References 
CTF SCHOOL VIDEO: https://youtube.com/shorts/79k8Ps82VaM?si=P_R8a5GROaRn8ZDv



# Challenge Name
Taste Of Sweetness

## My solve
**Flag:** `citadel{fru1tc4k3_4nd_c00k13s}`

This one was comparatively easier for me. I have learn MERN stack in the past and hence knew about the cookie feature before-hand. So when the website told me "How does website remember you" I just opened the inspect window and edited the cookie value from user to admin by going into Application part of inspect.

## What I learned
Cookie editing

## References 
None



# Challenge Name
Rotten Apple

## My solve
**Flag:** `citadel{b3tt3r_ROTt3n}`

My teammate put the ciphertext into google to realise it was `ROT cipher` after that we used Chatgpt to do the remain 13 and 47 shift and got the flag.

## What I learned
ROT Cipher

## References 
None



# Challenge Name
Randomly accessed Memory

## My solve
**Flag:** `citadel{w3_4r3_up_4ll_n1t3_t0_g1t_lucky}`

1.Since I saw 
```bash
clone it, pull it, reset it, stage it, 
commit, push it, fork, rebase it. 
merge it, branch it, tag it, log it, 
add it, stash it, diff, untrack it … 
```
I thought I just had to execute these commands using bash on the repo link given. So i went into my bash and i tried to clone it but the access was denied so I understood this wasn't the right way and hence i decided to look furthur.
2.My teammates started searching through all files and I started searching the commits. I found the first suspicious commit with the name `Remove secret chunk 3 file (history-only)` I loaded it and got a strange ciphertext. Putting it into chatgpt it told me that it was a base64 encode text and the decoded text is this: `dDBfZzF0X2x1Y2t5fQ== → t0_g1t_lucky}` now i knew that we are on the right path and hence we all started searching the commit history and eventually getting all the parts of the flag.
## What I learned
Reading the commit history of a repository.

## References 
None


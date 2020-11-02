# airodump with defensible checking for deauth
![image](https://user-images.githubusercontent.com/61967756/97809223-190bf280-1caf-11eb-806e-45c7c3a5c95e.png)
![image](https://user-images.githubusercontent.com/61967756/97870308-262fec80-1d56-11eb-820c-8739fe4e2287.png)

# compile
g++ -o airodump main.cpp dot11.cpp -lpcap -pthread

# execution
./airodump interface

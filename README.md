# lacpsimulator	
Python script that talk LACP (not fluently)	

Usage: python3 script.py [-mute] <interface1_name> <interface2_name> [...]

Made this python script to test specific scenario related to Cisco bug CSCwj01605  				
"Wrong dot1q private-vlan tag after LACP update"  		
https://bst.cisco.com/bugsearch/bug/CSCwj01605?rfs=qvred  

You can launch both script on different server to simulate suspended LACP state due to different port priority.

Dont forget to hardcode your own data:  
actor_system_priority=0xffff  
actor_system="aa:bb:cc:aa:bb:cc"  
actor_port_priority=0xff  


This parameter should be unique for both script if you want to test the suspended port scenario:  
actor_key=0x005d

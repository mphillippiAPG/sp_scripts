#!/bin/bash

capture_file=$1
port=$2

tshark -Vnnn -d udp.port==$port,cflow -r $capture_file  | awk '
BEGIN{sid=0;}
{
   if (/Frame [0-9]+/)
      {fr=substr($2, 1, length($2)-1)} 
   if (/Internet Protocol/)
      {ip=$6} 
   if(/FlowSequence/)
      {fs=$2} 
   if(/SourceId/)
   { sid=$2; }
 	if(/Observation Domain Id/)
 	{sid=$4;}
 	if (sid>0)
 	{	
 		msg="";
		info="frame " fr ", rtr " ip " seq " fs ", domid " sid;
     	if ((last_seq[sid]+1!=fs)&&(sid in last_seq))
	     	{msg="| MISSING FLOW: expected " last_seq[sid]+1 " got " fs;}
		print info,msg ;
	     
	     last_seq[sid]=fs;
	     sid=0;
     } 
}' 
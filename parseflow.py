#!/usr/bin/env python2

"""
Parseflow.py 

author: cbird@arbor.net

2021-11-14: (mphillippi) updated tshark executable location to
  point to '/usr/bin/env tshark' for cross-plat capabilities.

will take a pcap of netflow and compute the input
and output rates for all observed interfaces contained in the 
flow capture.  The pcap must contain flow from a single router

The output will generate an html file. Within the file all 
Input and Output snmp indexes have a checkbox by selecting the 
various interfaces a dynamic graph is created.  The graph allows
dynamic zooming any combination of interfaces can be graphed as well
by using this you now have an objective means to see flow
and, usually, eliminate SP as being the culprit of a tuning page 
mismatch.

Once the values are computed the bps rate is computed by
octets*8* sample_rate

pps is computed by
packets * sample_rate


With the graph we can then compare against the tuning page
for an interface.  It should be noted that the graph presented
shows 1 second sums instead of SP's 5 minute bin so the graphs
won't necessarily line up exactly.
"""
from optparse import OptionParser
import sys
import subprocess

agg_dur=1

parser=OptionParser()
parser.add_option("-r",
		  "--max_records",
		  dest="max_record",
		  default=-1,
		  help="Maximum number of flow records to parse")
parser.add_option("-s",
		  "--sample_rate",
		  dest="sample_rate",
		  help="configured sample rate for the router defaults to 1000",
		  default=1000)
parser.add_option("-f",
		  "--flowcap",
		  help="file containing flow to parse",
		  dest="infile")
parser.add_option("-o",
				   help="output file, leaving blank sends output to stdout",
				   dest="output_file",
				   default="flow_count.html")
parser.add_option("-p",
                   help="port to use as flow",
                   dest="flow_port",
                   default="2055")
parser.add_option("-a",
            help="average to this many seconds",
            dest="flow_average",
            default="300")
(options,args)=parser.parse_args()

if options.infile is None:
	sys.exit("no input file specified")

packets=[]
count={}

popen=None


html_template="""
<!DOCTYPE html>
<head>
    <meta http-equiv="Content-Type" content="text/html;charset=utf-8">
    <meta http-equiv="pragma" content="no-cache">
<style>
  .rblock{
    display:inline-block;

    padding: 20px;
    border-width: 1px;
    border-style: solid;
    border-color: orange;
     border-radius: 8px;
  }
  .rblock label {
  color: white;

  padding: 0px 0px;
  position: relative;
  background-color: cornflowerblue;
  /* Adjust these values to posiytion the title or label */
  top: -10px;
  left: 10px;
}
</style>
<script src="https://cdnjs.cloudflare.com/ajax/libs/dygraph/2.0.0/dygraph.js"></script>
<script src="https://code.jquery.com/jquery-1.12.4.js"></script>
<script language="javascript">
var data={ 
%s 
};
var rate_type;
function CreateRadioBlock(count,dir)
{   var block="";
    var c=count[dir];
    for(var ind in c.sort())
    {
        var i=c[ind];
        var r='<input type="checkbox" ';
        r+=' onchange="UpdateGraph()" ';
        r+='name="'+dir+'"';
        r+='id="'+dir+i+'" ';
        r+='value="'+i+'" >';
        r+=i+'</input>'
        block+="<li >"+r+"</li>";
    }
    return block;
}
function PopData()
{




    count={InputInt:[],
           OutputInt:[]}
    for(var t in data)
    {
        timeframe=data[t];

        for(var direction in timeframe)
        {
            for(var interface in timeframe[direction] )
            {
     
                    count[direction].push(interface);
            }
            var c=count[direction]
            count[direction]=c.filter(
                function(item,index)
                {
                    return c.indexOf(item)>=index
                })   
        }    
    }
    block=""
    for(var direction in count)
    {
        
        block+='<div class="rblock">';
        block+="<label>"+direction+"</label>";
        block+='<ul style="list-style-type:none">';
        block+=CreateRadioBlock(count,direction);
        block+="</ul>";
        
        block+="</div>";
        
    }
    block="<div>"+block+"</div>"
    $("#interfaces").html(block);
    
}
function GraphData(data) {

   new Dygraph(
       document.getElementById("rates"),
        data, 
        {
        legend: 'always',
        showRangeSelector: false,
        connectSeparatedPoints: true,
        ylabel: 'rates',
        axes: {
            y:{ axisLabelFormatter: function(y) {
                var range={K:[1e3,1e6],
                           M:[1e6,1e9],
                           G:[1e9,1e12],
                           T:[1e12,1e15],
                           P:[1e15,1e18],
                           E:[1e18,1e21]};
                for(var r in range)
                {
                    min=range[r][0];
                    max=range[r][1];
                    if (y>=min && y<=max)
                    {
                        return (y/min)+r;
                    }
                }
            }},
              x:{axisLabelFormatter: function(x){
              var d=new Date(x*1000);
              var dte=d.getMonth()+"/";
                  dte+=d.getDay()+" ";
                  dte+=d.getHours()+":";
                dte+=d.getMinutes()+":";
                dte+=d.getSeconds();
              return dte;
            }}
      
        },
        drawPoints : true,
        strokeWidth:2.0,
       }
    );
}
function UpdateGraph()
{
    var selected={InputInt:[],OutputInt:[]};
    var int_type=['InputInt','OutputInt'];
    rate_type=$("input[name='output_type']:checked").val();
    if (rate_type=="pps")
    {
    	rate_type="Packets";
    }
    if (rate_type=="bps")
    {
    	rate_type="Octets";
    }
    for(var i in int_type)
    {

        $("input[name='"+int_type[i]+"']:checked").each(
        function()
        {

            selected[int_type[i]].push(this.value);
        });
     }  
     var chart_data="";
     var header=[];
     var chart_header="time,";
     for(var t in data)
     {

        chart_data+=t+",";
        var sec=data[t];
        for (var d in int_type)
        {
            direction=int_type[d];
            for (var i in selected[direction])
            {
                var h=selected[direction][i]+"-"+direction;
                if (header.indexOf(h)<0)
                {
                    header.push(h);
                    header.push(h+rate_type+"Avg");
                }
                var int_index=selected[direction][i];
                var v=0;
                if (int_index in sec[direction])    
                {
                    v=sec[direction][int_index][rate_type];
                    v+=","+sec[direction][int_index][rate_type+"Avg"];
                }
                chart_data+=v+",";
            }
        }
         chart_data+="\\n";  
     }
   
     for(var i in header)
     {
        chart_header+=header[i]+","
     }

     GraphData(chart_header+"\\n"+chart_data.slice(0, -1));


}
</script>


</head>



<body onload="PopData()" >

    <div id="rates" style="width: 100%%; height: 400px" >
      
    </div>
    <div id="output_type" style="margin:20px">
        <input 
          onchange="UpdateGraph()" 
            type="radio" 
            value="pps" 
            name="output_type"
            >pps</input>
        <input 
        onchange="UpdateGraph()" 
            type="radio" 
            value="bps" 
            name="output_type"
            checked>bps</input>
        
    </div> 
    <div id="interfaces">
    </div>
   
</body>

</html>
"""




def Output2HTML():

  def GetRates(interface):
  	sample_rate=int(options.sample_rate)
  	return ','.join("%s:%s"%(t,(int(interface[t])/agg_dur)*sample_rate) for t in interface)

  def GetInterfaces(time_dir):
  	return ',\n\t\t'.join('%s:{%s}'%(i,GetRates(time_dir[i])) for i in time_dir)	

  def GetDirection(dir):

  	return ',\n\t'.join('%s:{%s}'%(i,GetInterfaces(dir[i])) for i in dir)	


  out=',\n'.join('%s:{%s}'%(t,GetDirection(count[t])) for t in sorted(count.iterkeys())).replace("'","")

  f=open(options.output_file,'w')
  f.write( html_template%out)
  f.close()

			


def aggregate_pcap():
	max_records=int(options.max_record)
	line={}
	count=0
	cmd="/usr/bin/env tshark -d udp.port==%s,cflow -r %s -T fields -e frame.time_epoch  -e cflow.inputint -e cflow.outputint -e cflow.packets -e cflow.octets "
	cmd=cmd%(options.flow_port,options.infile)
	
	popen = subprocess.Popen(cmd.split(), 
		                     stdout=subprocess.PIPE, 
		                     universal_newlines=True)
	for l in iter(popen.stdout.readline, ""):
		line=l.split()
		t=line[0].split('.')[0]
		try:
			inint=line[1].split(',')
		except IndexError:
			continue
		
		outint=line[2].split(',')
		pck=line[3].split(',')
		octets=line[4].split(',')
		for i in range(len(inint)):
			packet={'Epoch Time':t,
							'Octets':int(octets[i]),
							'Packets':int(pck[i]),
							'InputInt':int(inint[i]),
							'OutputInt':int(outint[i])
							 }
		
			packets.append(packet)
			count+=1
			if ((count %1000) ==0):
					sys.stdout.write("%sprocessing %s records"%("\b"*40,count))
					sys.stdout.flush()


		if ((max_records!=-1) and (count>max_records)):
			popen.kill()
			break
	


def update_count(c,p,dir,t):
  mul={'Octets':8,'Packets':1}
  iface_init={'Octets':0,
  'Packets':0}
  iface=p[dir]
  if iface not in c[dir]:
    c[dir][iface]=iface_init
  for j in ['Octets','Packets']:
    c[dir][iface][j]+=p[j]*mul[j]
  

def average_counts():
  l=sorted(count)
  mn=int(min(l))
  mx=int(max(l))
  totals={t:{} for t in range(mn,mx,int(options.flow_average))}
  for t in l:
    for d in count[t]:
      for i in count[t][d]:
        for op in ['Octets','Packets']:
         # print t,d,i,op,count[t][d][i][op]
          for tot in totals:
            
            if t>=tot:
           
              if d not in totals[tot]:
                totals[tot][d]={}
              if i not in totals[tot][d]:
                totals[tot][d][i]={}
              if op not in totals[tot][d][i] :
                totals[tot][d][i][op]=0
                totals[tot][d][i]['%sCount'%op]=0

              totals[tot][d][i][op]+=count[t][d][i][op]
              totals[tot][d][i]['%sCount'%op]+=1
              break

  for t  in totals:
    for d in totals[t]:
      for i in totals[t][d]:
        sample=totals[t][d][i]
        for op in ['Packets','Octets']:
          sample['%sAvg'%op]=sample[op]/sample['%sCount'%op]
  
  for t in l:
    for d in count[t]:
      for i in count[t][d]:
        for t1 in totals:
          if t>=t1:

            for op in ['Octets','Packets']:
              count[t][d][i]['%sAvg'%op]=totals[t1][d][i]['%sAvg'%op]
          break



def aggregate_counts():

  c=count
  for p in packets:

    t=p['Epoch Time']

    if t not in c:
      c[t]={'InputInt':{},'OutputInt':{}}

    for i in ['InputInt','OutputInt']:
      update_count(c[t],p,i,t)

def main():
	
	

  aggregate_pcap()
  print
  aggregate_counts()
  average_counts()

  Output2HTML()


if __name__ == '__main__':
	main()



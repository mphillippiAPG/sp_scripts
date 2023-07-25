#!/usr/bin/env python3
"""
author: cbird@arbor.net

description:

This script will compare interface.xml agains snmp.xml to determine valid interfaces
that should no longer be interface.xml.  If an interface exists in snmp.xml and 
interface.xml then the interface is kept.   In the event it's not then a second check
is performed.  If the interface gid exists as /base/data/interace/<interface gid> then
it is still kept.  The script will output to new_interface.xml.  Due to teh version
of element tree on sp not having a pretty function you need to do the follwoing 
if you want to make it human readable:

cat new_interface.xml | xmllint --format -

if you find the new_interface.xml is valid and want to make sp read it in
then you need to do the follwoing
1.  copy new_interface.xml /base/data/interface/interface.xml
2.  pfclient signal 39 ted

"""
import xml.etree.ElementTree as ET
import xml.dom.minidom
import os

snmp = ET.parse('snmp.xml')
interface = ET.parse('interface.xml')

int_root = interface.getroot()
interface_data = int_root.find('.//interface_data')

version = int(interface_data.attrib['version'])+1
release = int_root.attrib['release']

peakflow = ET.Element('peakflow')
peakflow.set('version', '1.0')
peakflow.set('release', release)
peakflow.set('msg_type', 'interface')
peakflow.set('msg_ver', '1')

interface_data = ET.SubElement(peakflow, 'interface_data')
interface_data.set('version', str(version))


def copy_interface(r, i):
    t = ET.SubElement(r, "intf")
    for a in i.attrib:
        t.set(a, i.attrib[a])
    return


for router in interface.findall('.//router'):
    router_name = router.attrib['name']
    router_gid = router.attrib['gid']
    r = ET.SubElement(interface_data, 'router')
    for a in router.attrib:
        r.set(a, router.attrib[a])
    for interface in router.findall('.//intf'):
        interface_name = interface.attrib['name']
        interface_index = interface.attrib['index']
        interface_gid = interface.attrib['gid']
        if (int(interface_index) == 0):
            copy_interface(r, interface)
        else:
            snmp_query = """.//router[@gid="%s"]/intf[@name="%s"]"""
            snmp_data = snmp.find(snmp_query % (router_gid, interface_name))
            if snmp_data is not None:
                copy_interface(r, interface)
            else:
                if os.path.exists('/base/data/traffic/interface/%s' % interface_gid):
                    copy_interface(r, interface)
xmlstr = xml.dom.minidom.parseString(
    ET.tostring(peakflow)).toprettyxml(indent="   ")
with open("new_interface.xml", "w") as f:
    f.write(xmlstr)

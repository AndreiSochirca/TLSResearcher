/**
 * Copyright (c) 2009 Andrei Sochirca, All Rights Reserved
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.  
 */
package com.smaxe.os.jna.pcap.support;

import com.smaxe.os.jna.pcap.Pcap;
import com.smaxe.os.jna.pcap.PcapLibrary;
import com.smaxe.os.jna.pcap.WinPcapLibrary;
import com.smaxe.os.jna.pcap.pcap_if;
import com.smaxe.os.jna.pcap.ref_pcap_if;
import com.sun.jna.Native;
import com.sun.jna.Platform;
import com.sun.jna.ptr.IntByReference;

import java.util.ArrayList;
import java.util.List;

/**
 * <code>PacketCaptureLibrary</code> - 'Packet Capture' library wrapper.
 * 
 * @author Andrei Sochirca
 */
public final class PacketCaptureLibrary extends Object {
    // fields
    private PcapLibrary pcap;
    private ref_pcap_if ref_pcap_if;
    private byte[] errbuf;
    
    /**
     * Constructor.
     */
    public PacketCaptureLibrary() {
        this.pcap = Platform.isWindows() ? (WinPcapLibrary) Native.loadLibrary("wpcap", WinPcapLibrary.class) :
            (PcapLibrary) Native.loadLibrary("pcap", PcapLibrary.class);
        if (this.pcap == null) throw new IllegalStateException("Failed to load native pcap library");
        
        this.errbuf = Pcap.createErrorBuffer();
    }
    
    /**
     * Returns 'pcap' library version.
     * 
     * @return 'pcap' library version
     */
    public String getVersion() {
        return pcap.pcap_lib_version();
    }
    
    /**
     * Finds all network devices.
     * 
     * @return network devices collection
     */
    public List<NetworkDevice> findAllNetworkDevices() {
        if (ref_pcap_if == null) {
            ref_pcap_if = new ref_pcap_if();
            
            final int pcap_findalldevs = pcap.pcap_findalldevs(ref_pcap_if, errbuf);
            if (pcap_findalldevs != 0) {
            	System.err.println("pcap.pcap_findalldevs returned " + pcap_findalldevs);
            	return new ArrayList<NetworkDevice>();
            }
        }
        
        List<NetworkDevice> networkDevices = new ArrayList<NetworkDevice>();
        
        for (pcap_if pcap_if : Pcap.iterate(ref_pcap_if)) {
        	IntByReference net = new IntByReference();
        	
        	pcap.pcap_lookupnet(pcap_if.name, net, new IntByReference(), errbuf);
        	
            networkDevices.add(new NetworkDevice(pcap, pcap_if, net.getValue()));
        }
        
        return networkDevices;
    }
    
    /**
     * Returns data link type name.
     * 
     * @param dataLinkType data link type value
     * @return data link type name
     */
    public String getDataLinkTypeName(final int dataLinkType) {
        return pcap.pcap_datalink_val_to_name(dataLinkType);
    }
    
    /**
     * Returns data link type description.
     * 
     * @param dataLinkType data link type value
     * @return data link type description
     */
    public String getDataLinkTypeDescription(final int dataLinkType) {
        return pcap.pcap_datalink_val_to_description(dataLinkType);
    }
    
    /**
     * Releases the resources acquired by the library.
     */
    public void release() {
        if (ref_pcap_if != null) {
            pcap.pcap_freealldevs(ref_pcap_if.getValue());
            ref_pcap_if = null;
        }
    }
}
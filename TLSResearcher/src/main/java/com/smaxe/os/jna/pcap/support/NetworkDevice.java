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

import com.smaxe.os.jna.pcap.*;
import com.smaxe.os.pcap.ByteUtils;
import com.smaxe.os.pcap.IPacketProcessor;

import com.sun.jna.Pointer;

import java.net.InetAddress;

/**
 * <code>NetworkDevice</code> - network interface device.
 * 
 * @author Andrei Sochirca
 */
public final class NetworkDevice extends Object {
    /**
     * <code>IListener</code> - listener.
     */
    public static interface IListener {
        /**
         * Notifies about the exception.
         * 
         * @param message error message
         * @param e exception
         */
        public void onException(final String message, final Exception e);
        
        /**
         * Notifies about log message.
         * 
         * @param message log message
         */
        public void onMessage(final String message);
    }
    
    /**
     * <code>ListenerAdapter</code> - {@link IListener} adapter.
     */
    public static class ListenerAdapter extends Object implements IListener {
        /**
         * Constructor.
         */
        public ListenerAdapter() {
        }
        
        // IListener implementation
        
        public void onException(final String message, final Exception e) {
        }
        
        public void onMessage(final String message) {
        }
    }
    
    /**
     * <code>EmptyPacketProcessor</code> - empty {@link IPacketProcessor} implementation.
     */
    private final static class EmptyPacketProcessor extends Object implements IPacketProcessor {
        /**
         * Constructor.
         */
        public EmptyPacketProcessor() {
        }
        
        // IPacketProcessor implementation
        
        public void onPacket(final int dataLinkType, final long timestamp, final byte[] data, final int dataOffset, final int dataLength) {
        }
    }
    
    /**
     * <code>PcapHandler</code> - {@link pcap_handler} implementation.
     */
    private final class PcapHandler extends Object implements pcap_handler {
        // fields
        private final int dataLinkType;
        private final byte[] buf;
        private int offset;
        
        /**
         * Constructor.
         * 
         * @param dataLinkType
         * @param bufferSize packet buffer size
         */
        public PcapHandler(final int dataLinkType, final int bufferSize) {
            this.dataLinkType = dataLinkType;
            this.buf = new byte[bufferSize];
            this.offset = 0;
        }
        
        // pcap_handler implementation
        
        public void callback(final String user, final pcap_pkthdr pkt_header, final Pointer pkt_data) {
            final long timestamp = (pkt_header.tv_sec.longValue() & 0xFFFFFFFF) * 1000 + (pkt_header.tv_usec.longValue() / 1000);
            final int length = pkt_header.caplen;
            
            if (offset + length > buf.length) offset = 0;
            
            pkt_data.read(0, buf, offset, length);
            
            processor.onPacket(dataLinkType, timestamp, buf, offset, length);
            
            offset += length;
        }
    }
    
    /**
     * <code>CaptureRunnable</code> - packet capture runnable.
     */
    private final class CaptureRunnable extends Object implements Runnable {
        // fields
        private pcap_t pcap_t = null;
        // keeps the reference to the packet-capture callback method
        @SuppressWarnings("unused")
        private PcapHandler handler = null;
        
        /**
         * Constructor.
         */
        public CaptureRunnable() {
        }
        
        /**
         * Checks if capture interface is open.
         * 
         * @return <code>true</code> if open; otherwise <code>false</code>
         */
        public boolean isOpen() {
            return pcap_t != null;
        }
        
        /**
         * Stops the capture.
         */
        public void stop() {
            pcap.pcap_breakloop(pcap_t);
        }
        
        // Runnable implementation
        
        public void run() {
            final byte[] errbuf = Pcap.createErrorBuffer();
            
            bpf_program bpf_program = null;        
            
            try {
                log("open packet capture interface " + pcap_if.name);
                
                pcap_t = pcap.pcap_open_live(pcap_if.name, snaplen, promisc, timeout, errbuf);
                if (pcap_t == null) throw new Exception("Failed to open packet capture interface " + pcap_if.name);
                
                if (filter != null) {
                    bpf_program = new bpf_program();
                    
                    final int pcap_compile = pcap.pcap_compile(pcap_t, bpf_program, filter, filterOptimize, filterNetmask);
                    
                    if (checkResult("compile filter '" + filter + "' (optimize=" + filterOptimize + ", netmask=" + filterNetmask + ")", pcap_compile)) {
                        final int pcap_setfilter = pcap.pcap_setfilter(pcap_t, bpf_program);
                        
                        checkResult("set filter", pcap_setfilter);
                    }
                }
                
                final int pcap_datalink = pcap.pcap_datalink(pcap_t);
                
                log("packet capture interface datalink is " + pcap_datalink);
                
                // entering the packet receive loop
                final int pcap_loop = pcap.pcap_loop(pcap_t, 0 /*cnt*/, handler = new PcapHandler(pcap_datalink, pcapBufferSize), "user" /*user*/);
                
                switch (pcap_loop) {
                    case -2: {
                        log("packet capture interface loop is stopped by user");
                    } break;
                }
            }
            catch (Exception e) {
                log("thrown exception", e);
            }
            finally {
                if (bpf_program != null) {
                    pcap.pcap_freecode(bpf_program);
                }
                
                pcap.pcap_close(pcap_t);
                
                handler = null;
                pcap_t = null;
            }
        }
        
        // inner use methods
        /**
         * Checks operation result and returns <code>true</code> on success,
         * or <code>false</code> on failure (listener is notified about failure also).
         * 
         * @param operation
         * @param result
         * @return <code>true</code> on success; <code>false</code> on failure
         */
        private boolean checkResult(final String operation, final int result) {
            switch (result) {
                case 0: {
                    log(operation + " ... success");
                    return true;
                }
                case -1: {
                    log(operation + " ... failure");
                    return false;
                }
                default: {
                    log(operation + " ... unexpected result " + result);
                    return false;
                }
            }
        }
        
        /**
         * Logs the message.
         * 
         * @param message
         */
        private void log(final String message) {
            listener.onMessage(message);
        }
        
        /**
         * Logs the exception.
         * 
         * @param message
         * @param e
         */
        private void log(final String message, final Exception e) {
            listener.onException(message, e);
        }
    }
    
    // static fields
    private final static IListener EMPTY_LISTENER = new ListenerAdapter();
    private final static IPacketProcessor EMPTY_PACKET_PROCESSOR = new EmptyPacketProcessor();
    
    // fields
    private final PcapLibrary pcap;
    private final pcap_if pcap_if;
    private final int net;
    
    private IListener listener = EMPTY_LISTENER;
    private IPacketProcessor processor = EMPTY_PACKET_PROCESSOR;
    
    private Thread captureThread = null;
    private CaptureRunnable captureRunnable = null;
    
    // configuration
    // interface configuration
    private int pcapBufferSize = 4 * 1024 * 1024;
    private int snaplen = 64 * 1024;
    private int promisc = Pcap.PCAP_OPENFLAG_PROMISCUOUS;
    private int timeout = 20;
    // filter configuration
    private String filter = null;
    private int filterOptimize = 0;
    private int filterNetmask = 0;
    
    /**
     * Constructor.
     * 
     * @param pcap pcap library reference
     * @param pcap_if pcap interface
     * @param net
     */
    public NetworkDevice(PcapLibrary pcap, pcap_if pcap_if, int net) {
        if (pcap == null) throw new IllegalArgumentException("Parameter 'pcap' is null");
        if (pcap_if == null) throw new IllegalArgumentException("Parameter 'pcap_if' is null");
        
        this.pcap = pcap;
        this.pcap_if = pcap_if;
        this.net = net;
    }
    
    /**
     * @return packet capture interface name
     */
    public String getName() {
        return pcap_if.name;
    }
    
    /**
     * @return packet capture interface description
     */
    public String getDescription() {
        return pcap_if.description;
    }
    
    /**
     * Returns network interface address.
     * 
     * @return address
     */
    public InetAddress getAddress() {
        return pcap_if.addresses == null ? null : getAddress(pcap_if.addresses.addr);
    }
    
    /**
     * Returns network interface broadcast address.
     * 
     * @return broadcast address, <code>null</code> if broadcast isn't supported
     */
    public InetAddress getBroadcastAddress() {
        return pcap_if.addresses == null ? null : getAddress(pcap_if.addresses.broadaddr);
    }
    
    /**
     * Returns network interface destination address (<code>null</code>
     * if interface is not Point-to-Point).
     * 
     * @return destination address, <code>null</code> if interface is not Point-to-Point
     */
    public InetAddress getDestinationAddress() {
        return pcap_if.addresses == null ? null : getAddress(pcap_if.addresses.dstaddr);
    }
    
    /**
     * Returns netmask.
     * 
     * @return net mask
     */
    public InetAddress getNetmask() {
        return pcap_if.addresses == null ? null : getAddress(pcap_if.addresses.netmask);
    }
    
    /**
     * Returns ip.
     * 
     * @return ip
     */
    public String getIP() {
    	if (pcap_if.addresses == null) return "";
    	
    	final byte[] ip = getIP(pcap_if.addresses.addr);
    	final byte[] net = getNet();
    	
        return ByteUtils.toIPv4String(ip[0] == net[0] ? ip : net, 0 /*dataOffset*/);
    }
    
    /**
     * Returns <code>true</code> for loopback device; otherwise <code>false</code>.
     * 
     * @return <code>true</code> for loopback device; otherwise <code>false</code>
     */
    public boolean isLoopback() {
        return pcap_if.flags == 0x01;
    }
    
    /**
     * Sets buffer size (default: 4MB).
     * <p> Note:
     * <br> Fix-sized, circular buffer is used to store packet content.
     * 
     * @param size buffer size
     */
    public void setBufferSize(final int size) {
        this.pcapBufferSize = size;
    }
    
    /**
     * Sets the filter.
     * <p> Please check http://www.winpcap.org/docs/docs_40_2/html/group__language.html
     * for the 'Filtering expression syntax' details.
     * 
     * @param filter
     */
    public void setFilter(final String filter) {
        this.filter = filter;
    }
    
    /**
     * Sets the listener.
     * 
     * @param listener
     */
    public void setListener(final IListener listener) {
        this.listener = listener == null ? EMPTY_LISTENER : listener;
    }
    
    /**
     * Sets read timeout (in milliseconds, default: 20).
     * 
     * @param timeout
     */
    public void setReadTimeout(final int timeout) {
        this.timeout = timeout;
    }
    
    /**
     * Checks if packet capture is started.
     * 
     * @return <code>true</code> if started; otherwise <code>false</code> 
     */
    public boolean isStarted() {
        return captureRunnable != null;
    }
    
    /**
     * Checks if capture interface is open.
     * 
     * @return <code>true</code> if open; otherwise <code>false</code>
     */
    public boolean isOpen() {
        return captureRunnable.isOpen();
    }
    
    /**
     * Starts packet capture.
     * 
     * @param packetProcessor packet processor
     */
    public void startPacketCapture(final IPacketProcessor packetProcessor) {
        if (isStarted()) return;
        
        this.processor = packetProcessor == null ? EMPTY_PACKET_PROCESSOR : packetProcessor;
        this.captureThread = new Thread(captureRunnable = new CaptureRunnable(), getCaptureThreadName());
        
        this.captureThread.start();
    }
    
    /**
     * Stops packet capture.
     * 
     * @return packet processor that was used for packet processing
     */
    public IPacketProcessor stopPacketCapture() {
        if (captureRunnable != null) {
            captureRunnable.stop();
            captureRunnable = null;
            captureThread = null;
        }
        
        IPacketProcessor processor = this.processor;
        
        this.processor = EMPTY_PACKET_PROCESSOR;
        
        return processor;
    }
    
    // inner use methods
    /**
     * @return capture thread name
     */
    private String getCaptureThreadName() {
        String description = getDescription();
        
        description = description == null ? "default" : description;
        
        return "packet-capture [" + (description.length() < 16 ? description : description.substring(0, 16)).trim() + "]"; 
    }
    
    /**
     * Returns {@link InetAddress} instance by <code>addr</code>.
     * 
     * @param addr
     * @return inet address
     */
    private InetAddress getAddress(final sockaddr addr) {
        if (addr == null) return null;
        
        try {
            return InetAddress.getByAddress(getIP(addr));
        }
        catch (Exception e) {
            return null;
        }
    }
    
    /**
     * Returns IP bytes by <code>addr</code>.
     * 
     * @param addr
     * @return ip
     */
    private byte[] getIP(final sockaddr addr) {
        byte[] ip = new byte[16];
        
        if (addr != null) {
            System.arraycopy(addr.sa_data, 0, ip, 0, Math.min(ip.length, addr.sa_data.length));
        }
        
        return ip;
    }
    
    /**
     * @return net
     */
    private byte[] getNet() {
        byte[] ip  = new byte[4];
        
        for (int i = 0; i < 4; i++) {
            ip[i] = (byte) ((net >> (8 * i)) & 0xFF);
        }
        
        return ip;
    }
}
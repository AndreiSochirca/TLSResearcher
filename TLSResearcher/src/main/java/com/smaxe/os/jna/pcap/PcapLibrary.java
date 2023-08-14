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
package com.smaxe.os.jna.pcap;

import com.sun.jna.Library;
import com.sun.jna.Pointer;
import com.sun.jna.ptr.IntByReference;

/**
 * <code>PcapLibrary</code> - pcap library.
 * 
 * <p> Note:
 * <br> Methods that are not mentioned:
 * <br> - int pcap_next_ex(pcap_t *p, struct pcap_pkthdr **pkt_header, const u_char **pkt_data)
 * <br> - FILE* pcap_file(pcap_t *p)
 * <br> - FILE* pcap_dump_file(pcap_dumper_t *p)
 * 
 * @author Andrei Sochirca
 */
public interface PcapLibrary extends Library {
    /**
     * Open a live capture from the network.
     * <pre>
     * pcap_open_live() is used to obtain a packet capture descriptor to look at packets
     * on the network. device is a string that specifies the network device to open;
     * on Linux systems with 2.2 or later kernels, a 
     * <code>device</code> argument of "any" or NULL can be used to capture packets from all interfaces.
     * <code>snaplen</code> specifies the maximum number of bytes to capture.
     * If this value is less than the size of a packet that is captured, only the first snaplen bytes
     * of that packet will be captured and provided as packet data. A value of 65535 should be sufficient, on most if not all networks,
     * to capture all the data available from the packet.
     * <code>promisc</code> specifies if the interface is to be put into promiscuous mode.
     * (Note that even if this parameter is false, the interface could well be in promiscuous mode for some other reason.)
     * For now, this doesn't work on the "any" device; if an argument of "any" or NULL is supplied,
     * the promisc flag is ignored.
     * <code>to_ms</code> specifies the read timeout in milliseconds.
     * The read timeout is used to arrange that the read not necessarily return immediately
     * when a packet is seen, but that it wait for some amount of time to allow
     * more packets to arrive and to read multiple packets from the OS kernel in one operation.
     * Not all platforms support a read timeout; on platforms that don't, the read timeout is ignored.
     * A zero value for to_ms, on platforms that support a read timeout, will cause a read
     * to wait forever to allow enough packets to arrive, with no timeout.
     * <code>errbuf</code> is used to return error or warning text. It will be set to error text
     * when pcap_open_live() fails and returns NULL. errbuf may also be set to warning text
     * when pcap_open_live() succeds; to detect this case the caller should store a
     * zero-length string in errbuf before calling pcap_open_live() and display
     * the warning to the user if errbuf is no longer a zero-length string.
     * </pre>
     * 
     * @param device
     * @param snaplen
     * @param promisc
     * @param to_ms
     * @param errbuf
     * @return connection descriptor
     */
    public pcap_t pcap_open_live(String device, int snaplen, int promisc, int to_ms, byte[] errbuf);
    
    /**
     * Create a <code>pcap_t</code> structure without starting a capture.
     * <pre>
     * pcap_open_dead() is used for creating a pcap_t structure to use when calling the other functions in libpcap.
     * It is typically used when just using libpcap for compiling BPF code.
     * </pre>
     * 
     * @param linktype
     * @param snaplen
     * @return connection descriptor
     */
    public pcap_t pcap_open_dead(int linktype, int snaplen);
    
    /**
     * Open a savefile in the tcpdump/libpcap format to read packets.
     * <pre>
     * pcap_open_offline() is called to open a "savefile" for reading. fname specifies the name of the file to open.
     * The file has the same format as those used by tcpdump(1) and tcpslice(1).
     * The name "-" in a synonym for stdin. Alternatively, you may call pcap_fopen_offline()
     * to read dumped data from an existing open stream fp.
     * Note that on Windows, that stream should be opened in binary mode.
     * errbuf is used to return error text and is only set when pcap_open_offline()
     * or pcap_fopen_offline() fails and returns NULL.
     * </pre>
     * 
     * @param fname
     * @param errbuf
     * @return connection descriptor
     */
    public pcap_t pcap_open_offline(String fname, byte[] errbuf);
    
    /**
     * Open a file to write packets.
     * <pre>
     * pcap_dump_open() is called to open a "savefile" for writing.
     * The name "-" in a synonym for stdout. NULL is returned on failure.
     * <code>p</code> is a pcap struct as returned by pcap_open_offline() or pcap_open_live().
     * <code>fname</code> specifies the name of the file to open.
     * Alternatively, you may call pcap_dump_fopen() to write data to an existing open stream fp.
     * Note that on Windows, that stream should be opened in binary mode.
     * If NULL is returned, pcap_geterr() can be used to get the error text.
     * </pre>
     * 
     * @param p
     * @param fname
     * @return pcap savefile descriptor
     */
    public pcap_dumper_t pcap_dump_open(pcap_t p, String fname);
    
    /**
     * Switch between blocking and nonblocking mode.
     * <pre>
     * pcap_setnonblock() puts a capture descriptor, opened with pcap_open_live(),
     * into "non-blocking" mode, or takes it out of "non-blocking" mode, depending on whether
     * the nonblock argument is non-zero or zero. It has no effect on "savefiles".
     * If there is an error, -1 is returned and errbuf is filled in with an appropriate error message;
     * otherwise, 0 is returned. In "non-blocking" mode, an attempt to read from
     * the capture descriptor with pcap_dispatch() will, if no packets are currently
     * available to be read, return 0 immediately rather than blocking waiting for packets to arrive.
     * pcap_loop() and pcap_next() will not work in "non-blocking" mode.
     * </pre>
     * 
     * @param p
     * @param nonblock
     * @param errbuf
     * @return <code>-1</code> if error; otherwise <code>false</code>
     */
    public int pcap_setnonblock(pcap_t p, int nonblock, byte[] errbuf);
    
    /**
     * Get the "non-blocking" state of an interface.
     * <pre>
     * pcap_getnonblock() returns the current "non-blocking" state of the capture descriptor;
     * it always returns 0 on "savefiles".
     * If there is an error, -1 is returned and errbuf is filled in with an appropriate error message.
     * </pre>
     * 
     * @param p
     * @param errbuf
     * @return non-blocking state, <code>-1</code> if error
     */
    public int pcap_getnonblock(pcap_t p, byte[] errbuf);
    
    /**
     * Construct a list of network devices that can be opened with pcap_open_live().
     * <pre>
     * Note that there may be network devices that cannot be opened with pcap_open_live()
     * by the process calling pcap_findalldevs(), because, for example,
     * that process might not have sufficient privileges to open them for capturing;
     * if so, those devices will not appear on the list.) alldevsp is set to point
     * to the first element of the list; each element of the list is of type pcap_if_t,
     * </pre>
     * 
     * @param alldevsp
     * @param errbuf
     * @return <code>-1</code> is returned on failure; <code>0</code> is returned on success.
     */
    public int pcap_findalldevs(ref_pcap_if alldevsp, byte[] errbuf);
    
    /**
     * Free an interface list returned by pcap_findalldevs().
     * <pre>
     * pcap_freealldevs() is used to free a list allocated by pcap_findalldevs().
     * </pre>
     * 
     * @param alldevsp
     */
    public void pcap_freealldevs(pcap_if alldevsp);
    
    /**
     * Return the first valid device in the system.
     * <pre>
     * Returns a network device suitable for use with pcap_open_live()
     * and pcap_lookupnet(). If there is an error, <code>null</code> is returned
     * and <code>errbuf</code> is filled in with an appropriate error message.
     * </pre>
     * 
     * @param errbuf
     * @return network device name
     */
    @Deprecated
    public String pcap_lookupdev(byte[] errbuf);
    
    /**
     * Return the subnet and netmask of an interface.
     * <pre>
     * pcap_lookupnet() is used to determine the network number and mask associated
     * with the network device device. Both netp and maskp are int pointers.
     * A return of <code>-1</code> indicates an error in which case errbuf is filled in
     * with an appropriate error message.
     * </pre>
     * 
     * @param device
     * @param netp
     * @param maskp
     * @param errbuf
     * @return <code>-1</code> on error; <code>0</code> on success
     */
    public int pcap_lookupnet(String device, IntByReference netp, IntByReference maskp, byte[] errbuf);
    
    /**
     * Collect a group of packets.
     * <pre>
     * pcap_dispatch() is used to collect and process packets.
     * <code>cnt</code> specifies the maximum number of packets to process before returning.
     * This is not a minimum number; when reading a live capture, only one bufferful of packets
     * is read at a time, so fewer than cnt packets may be processed.
     * A cnt of -1 processes all the packets received in one buffer when reading a live capture,
     * or all the packets in the file when reading a ``savefile''.
     * <code>callback</code> specifies a routine to be called with three arguments:
     * a u_char pointer which is passed in from pcap_dispatch(), a const struct pcap_pkthdr pointer,
     * and a const u_char pointer to the first caplen (as given in the struct pcap_pkthdr a pointer
     * to which is passed to the callback routine) bytes of data from the packet (which won't
     * necessarily be the entire packet; to capture the entire packet, you will have to provide
     * a value for snaplen in your call to pcap_open_live() that is sufficiently large to get all
     * of the packet's data - a value of 65535 should be sufficient on most if not all networks).
     * The number of packets read is returned.
     * 0 is returned if no packets were read from a live capture
     * (if, for example, they were discarded because they didn't pass the packet filter,
     * or if, on platforms that support a read timeout that starts before any packets arrive,
     * the timeout expires before any packets arrive, or if the file descriptor for the capture
     * device is in non-blocking mode and no packets were available to be read) or if no more
     * packets are available in a ``savefile.''
     * A return of -1 indicates an error in which case pcap_perror() or pcap_geterr() may be used
     * to display the error text. A return of -2 indicates that the loop terminated due to a call
     * to pcap_breakloop() before any packets were processed.
     * If your application uses pcap_breakloop(), make sure that you explicitly check for -1 and -2,
     * rather than just checking for a return value < 0.
     * </pre>
     * 
     * @param p
     * @param cnt
     * @param callback
     * @param user
     * @return <code>-1</code> on an error, <code>0</code> if cnt is exhausted,
     * <code>-2</code> if the loop terminated due to a call to pcap_breakloop()
     * before any packets were processed
     */
    public int pcap_dispatch(pcap_t p, final int cnt, pcap_handler callback, String user);
    
    /**
     * Collect a group of packets.
     * <pre>
     * pcap_loop() is similar to pcap_dispatch() except it keeps reading packets
     * until cnt packets are processed or an error occurs.
     * It does not return when live read timeouts occur. Rather, specifying a non-zero
     * read timeout to pcap_open_live() and then calling pcap_dispatch() allows
     * the reception and processing of any packets that arrive when the timeout occurs.
     * A negative cnt causes pcap_loop() to loop forever (or at least until an error occurs).
     * -1 is returned on an error; 0 is returned if cnt is exhausted;
     * -2 is returned if the loop terminated due to a call to pcap_breakloop()
     * before any packets were processed.
     * If your application uses pcap_breakloop(), make sure that you explicitly check for -1 and -2,
     * rather than just checking for a return value < 0.
     * </pre>
     * 
     * @param p
     * @param cnt
     * @param callback
     * @param user
     * @return <code>-1</code> on an error, <code>0</code> if cnt is exhausted,
     * <code>-2</code> if the loop terminated due to a call to pcap_breakloop()
     * before any packets were processed
     */
    public int pcap_loop(pcap_t p, final int cnt, pcap_handler callback, String user);
    
    /**
     * Return the next available packet.
     * <pre>
     * pcap_next() reads the next packet (by calling pcap_dispatch() with a cnt of 1)
     * and returns a u_char pointer to the data in that packet. (The pcap_pkthdr struct
     * for that packet is not supplied.) NULL is returned if an error occured, or if no packets
     * were read from a live capture (if, for example, they were discarded because they didn't
     * pass the packet filter, or if, on platforms that support a read timeout that starts before
     * any packets arrive, the timeout expires before any packets arrive, or if the file descriptor
     * for the capture device is in non-blocking mode and no packets were available to be read),
     * or if no more packets are available in a ``savefile.'' Unfortunately, there is no way
     * to determine whether an error occured or not.
     * </pre>
     * 
     * @param p
     * @param h
     * @return read data
     */
    public byte[] pcap_next(pcap_t p, pcap_pkthdr h);
    
    /**
     * Set a flag that will force pcap_dispatch() or pcap_loop() to return rather than looping.
     * <pre>
     * They will return the number of packets that have been processed so far,
     * or -2 if no packets have been processed so far. This routine is safe to use
     * inside a signal handler on UNIX or a console control handler on Windows,
     * as it merely sets a flag that is checked within the loop.
     * The flag is checked in loops reading packets from the OS - a signal by itself
     * will not necessarily terminate those loops - as well as in loops processing
     * a set of packets returned by the OS. Note that if you are catching signals
     * on UNIX systems that support restarting system calls after a signal,
     * and calling pcap_breakloop() in the signal handler, you must specify,
     * when catching those signals, that system calls should NOT be restarted by that signal.
     * Otherwise, if the signal interrupted a call reading packets in a live capture,
     * when your signal handler returns after calling pcap_breakloop(), the call will be restarted,
     * and the loop will not terminate until more packets arrive and the call completes.
     * </pre>
     * 
     * @param p
     */
    public void pcap_breakloop(pcap_t p);
    
    /**
     * Send a raw packet.
     * <pre>
     * This function allows to send a raw packet to the network.
     * p is the interface that will be used to send the packet, buf contains the data
     * of the packet to send (including the various protocol headers),
     * size is the dimension of the buffer pointed by buf, i.e. the size of the packet to send.
     * The MAC CRC doesn't need to be included, because it is transparently calculated
     * and added by the network interface driver.
     * The return value is <code>0</code> if the packet is succesfully sent, <code>-1</code> otherwise.
     * </pre>
     * 
     * @param p
     * @param buf
     * @param size
     * @return <code>0</code> if the packet is succesfully sent; otherwise <code>-1</code>
     */
    public int pcap_sendpacket(pcap_t p, byte[] buf, int size);
    
    /**
     * Save a packet to disk.
     * <pre>
     * pcap_dump() outputs a packet to the "savefile" opened with pcap_dump_open().
     * Note that its calling arguments are suitable for use with pcap_dispatch() or pcap_loop().
     * If called directly, the user parameter is of type pcap_dumper_t as returned
     * by pcap_dump_open().
     * </pre>
     * 
     * @param user
     * @param h
     * @param sp
     */
    public void pcap_dump(String user, pcap_pkthdr h, byte[] sp);
    
    /**
     * Return the file position for a "savefile".
     * <pre>
     * pcap_dump_ftell() returns the current file position for the "savefile", representing
     * the number of bytes written by pcap_dump_open() and pcap_dump().
     * <code>-1</code> is returned on error.
     * </pre>
     * 
     * @param p
     * @return <code>-1</code> on error
     */
    public long pcap_dump_ftell(pcap_dumper_t p);
    
    /**
     * Compile a packet filter, converting an high level filtering expression in a program
     * that can be interpreted by the kernel-level filtering engine.
     * <pre>
     * pcap_compile() is used to compile the string str into a filter program. program
     * is a pointer to a bpf_program struct and is filled in by pcap_compile().
     * optimize controls whether optimization on the resulting code is performed.
     * netmask specifies the IPv4 netmask of the network on which packets are being captured;
     * it is used only when checking for IPv4 broadcast addresses in the filter program.
     * If the netmask of the network on which packets are being captured isn't known
     * to the program, or if packets are being captured on the Linux "any" pseudo-interface
     * that can capture on more than one network, a value of 0 can be supplied;
     * tests for IPv4 broadcast addreses won't be done correctly,
     * but all other tests in the filter program will be OK.
     * A return of -1 indicates an error in which case pcap_geterr() may be used to display
     * the error text.
     * </pre>
     * 
     * @param p
     * @param fp
     * @param str
     * @param optimize
     * @param netmask
     * @return <code>-1</code> on error
     */
    public int pcap_compile(pcap_t p, bpf_program fp, String str, int optimize, int netmask);
    
    /**
     * Compile a packet filter without the need of opening an adapter. This function converts
     * an high level filtering expression (see Filtering expression syntax) in a program
     * that can be interpreted by the kernel-level filtering engine.
     * <pre>
     * pcap_compile_nopcap() is similar to pcap_compile() except that instead of passing
     * a pcap structure, one passes the snaplen and linktype explicitly.
     * It is intended to be used for compiling filters for direct BPF usage, without necessarily
     * having called pcap_open().
     * A return of -1 indicates an error; the error text is unavailable. (pcap_compile_nopcap()
     * is a wrapper around pcap_open_dead(), pcap_compile(), and pcap_close();
     * the latter three routines can be used directly in order to get the error text
     * for a compilation error.)
     * </pre>
     * 
     * @param snaplen_arg
     * @param linktype_arg
     * @param fp
     * @param str
     * @param optimize
     * @param netmask
     * @return <code>-1</code> on error
     */
    public int pcap_compile_nopcap(int snaplen_arg, int linktype_arg, bpf_program fp, String str, int optimize, int netmask);
    
    /**
     * Associate a filter to a capture.
     * <pre>
     * pcap_setfilter() is used to specify a filter program. fp is a a bpf_program struct,
     * usually the result of a call to pcap_compile().
     * -1 is returned on failure, in which case pcap_geterr() may be used to display the error text; 0 is returned on success.
     * </pre>
     * 
     * @param p
     * @param fp
     * @return <code>-1</code> on failure, <code>0</code> on success
     */
    public int pcap_setfilter(pcap_t p, bpf_program fp);
    
    /**
     * Free a filter.
     * <pre>
     * pcap_freecode() is used to free up allocated memory pointed to by a bpf_program struct
     * generated by pcap_compile() when that BPF program is no longer needed,
     * for example after it has been made the filter program for a pcap structure by a call to pcap_setfilter().
     * </pre>
     * 
     * @param fp
     */
    public void pcap_freecode(bpf_program fp);
    
    /**
     * Return the link layer of an adapter.
     * <pre>
     * returns the link layer type; link layer types it can return include: check the docs
     * <pre>
     * 
     * @param p
     * @return link layer of an adapter
     */
    public int pcap_datalink(pcap_t p);
    
    /**
     * List datalinks.
     * <pre>
     * pcap_list_datalinks() is used to get a list of the supported data link types
     * of the interface associated with the pcap descriptor.
     * pcap_list_datalinks() allocates an array to hold the list and sets *dlt_buf.
     * The caller is responsible for freeing the array.
     * -1 is returned on failure; otherwise, the number of data link types in the array is returned.
     * <pre>
     * 
     * @param p
     * @param dlt_buf
     * @return number of data link types; <code>-1</code> on failure
     */
    public int pcap_list_datalinks(pcap_t p, Pointer dlt_buf);
    
    /**
     * Set the current data link type of the pcap descriptor to the type specified by dlt.
     * 
     * @param p
     * @param dlt
     * @return <code>-1</code> on failure.
     */
    public int pcap_set_datalink(pcap_t p, int dlt);
    
    /**
     * Translates a data link type name, which is a DLT_ name with the DLT_ removed,
     * to the corresponding data link type value.
     * The translation is case-insensitive.
     * 
     * @param name
     * @return <code>-1</code> on failure.
     */
    public int pcap_datalink_name_to_val(String name);
    
    /**
     * Translates a data link type value to the corresponding data link type name.
     * 
     * @param dlt
     * @return data link type name, <code>null</code> on failure
     */
    public String pcap_datalink_val_to_name(int dlt);    
    
    /**
     * Translates a data link type value to a short description of that data link type
     * 
     * @param dlt
     * @return data link type description, <code>null</code> on failure
     */
    public String pcap_datalink_val_to_description(int dlt);    
    
    /**
     * Returns the dimension of the packet portion (in bytes) that is delivered to the application.
     * <pre>
     * pcap_snapshot() returns the snapshot length specified when pcap_open_live was called.
     * </pre>
     * 
     * @param p
     * @return snapshot length
     */
    public int pcap_snapshot(pcap_t p);
    
    /**
     * Returns <code>true</code> if the current savefile uses a different byte order than the current system.
     * 
     * @param p
     * @return <code>true</code> if the current savefile uses a different byte order than the current system;
     * otherwise <code>false</code>
     */
    public int pcap_is_swapped(pcap_t p);    
    
    /**
     * Returns the major version number of the pcap library used to write the savefile.
     * 
     * @param p
     * @return major version number
     */
    public int pcap_major_version(pcap_t p);
    
    /**
     * Returns the minor version number of the pcap library used to write the savefile.
     * 
     * @param p
     * @return minor version number
     */
    public int pcap_minor_version(pcap_t p);
    
    /**
     * Return statistics on current capture.
     * <pre>
     * pcap_stats() returns <code>0</code> and fills in a pcap_stat struct. The values represent
     * packet statistics from the start of the run to the time of the call. 
     * If there is an error or the underlying packet capture doesn't support packet statistics,
     * <code>-1</code> is returned and the error text can be obtained with pcap_perror() or pcap_geterr().
     * pcap_stats() is supported only on live captures, not on "savefiles";
     * no statistics are stored in "savefiles", so no statistics are available when reading from a "savefile".
     * </pre>
     * 
     * @param p
     * @param ps
     * @return <code>-1</code> on error; <code>0</code> on success
     */
    public int pcap_stats(pcap_t p, pcap_stat ps);
    
    /**
     * Prints the text of the last pcap library error on stderr, prefixed by prefix.
     * 
     * @param p
     * @param prefix
     */
    public void pcap_perror(pcap_t p, String prefix);
    
    /**
     * Returns the error text pertaining to the last pcap library error.
     * <pre>
     * the pointer Return will no longer point to a valid error message string after the pcap_t passed to it is closed;
     * you must use or copy the string before closing the pcap_t.
     * </pre>
     * 
     * @param p
     * @return last error text
     */
    public String pcap_geterr(pcap_t p);
    
    /**
     * Provided in case strerror() isn't available.
     * 
     * @param error
     * @return error string
     */
    public String pcap_strerror(int error);
    
    /**
     * Returns a string giving information about the version of the libpcap library being used;
     * note that it contains more information than just a version number.
     * 
     * @return library version
     */
    public String pcap_lib_version();
    
    /**
     * Close the files associated with p and deallocates resources.
     * 
     * @param p
     */
    public void pcap_close(pcap_t p);
    
    /**
     * Flushes the output buffer to the ``savefile,'' so that any packets written
     * with pcap_dump() but not yet written to the ``savefile'' will be written.
     * 
     * @param p
     * @return <code>-1</code> is returned on error, <code>0</code> on success.
     */
    public int pcap_dump_flush(pcap_dumper_t p);
    
    /**
     * Closes a savefile.
     * 
     * @param p
     */
    public void pcap_dump_close(pcap_dumper_t p);
}
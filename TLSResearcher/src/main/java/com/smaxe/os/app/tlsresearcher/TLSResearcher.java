/**
 * Copyright (c) 2023 Andrei Sochirca, All Rights Reserved
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
package com.smaxe.os.app.tlsresearcher;

import java.util.List;

import com.smaxe.os.jna.pcap.support.NetworkDevice;
import com.smaxe.os.jna.pcap.support.PacketCaptureLibrary;
import com.smaxe.os.pcap.Packet;
import com.smaxe.os.pcap.PacketProcessor;

/**
 * <code>TLSResearcher</code> - TLS Researcher entry point.
 * 
 * @author Andrei Sochirca
 */
public final class TLSResearcher extends Object {

	/**
	 * Application entry point.
	 * 
	 * @param args
	 */
	public static void main(final String... args) {
		System.out.println("Hello, World! I am TLS Researcher");
		
		PacketCaptureLibrary library = new PacketCaptureLibrary();
		
		System.out.println();
		System.out.println("PcapLibrary version: " + library.getVersion());
		System.out.println();
		
		final List<NetworkDevice> networkDevices = library.findAllNetworkDevices();
		
		for (NetworkDevice device : networkDevices) {
			System.out.println("Device: " + device.getName() + " : " + device.getDescription() + " : " + device.getIP());
		}
		
		System.out.println();
		
		final NetworkDevice device = networkDevices.get(0);
		
		device.setListener(new NetworkDevice.IListener() {
			@Override
			public void onMessage(final String message) {
				System.out.println("NetworkDevice#IListener.onMessage: " + message);
			}
			@Override
			public void onException(final String message, final Exception e) {
				System.out.println("NetworkDevice#IListener.onException: " + message);
				e.printStackTrace();
			}
		});
		
		device.startPacketCapture(new PacketProcessor() {
			@Override
		    protected void onTcpPacket(final Packet.TcpHeader header, final byte[] data, final int dataOffset, final int dataLength) {
				System.out.println("PacketProcessor.onTcpPacket: " + dataLength + " " + header);
		    }
		});
	}
}
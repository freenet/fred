/*
 * This code is part of Freenet. It is distributed under the GNU General Public License, version 2 (or at your option
 * any later version). See http://www.gnu.org/ for further details of the GPL.
 */
package freenet.tools;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.net.SocketException;

import freenet.node.fcp.AddPeer;
import freenet.node.fcp.FCPMessage;
import freenet.node.fcp.FCPServer;
import freenet.node.fcp.MessageInvalidException;
import freenet.node.fcp.NodeHelloMessage;
import freenet.support.SimpleFieldSet;
import freenet.support.io.LineReadingInputStream;

/**
 * Connects to a FCP server and adds a reference
 * 
 */
public class AddRef
{

	private static final String CONST_MSG_HELP = "Please provide a file name as the first argument.";

	private static final int CONST_SOCKET_TIMEOUT = 2000;
	private static final int CONST_SLEEP = 3000;

	/**
	 * Connects to a FCP server and adds a reference
	 * 
	 * @param args
	 */
	public static void main(String[] args)
	{
		if (args.length < 1)
		{
			System.err.println(CONST_MSG_HELP);
			System.exit(-1);
		}

		final File reference = new File(args[0]);
		if ((reference == null) || !(reference.isFile()) || !(reference.canRead()))
		{
			System.err.println(CONST_MSG_HELP);
			System.exit(-1);
		}

		new AddRef(reference);
	}

	/**
	 * @param reference
	 */
	AddRef(File reference)
	{
		Socket fcpSocket = null;

		FCPMessage fcpm;
		SimpleFieldSet sfs = new SimpleFieldSet(true);

		try
		{
			fcpSocket = new Socket("127.0.0.1", FCPServer.DEFAULT_FCP_PORT);
			fcpSocket.setSoTimeout(CONST_SOCKET_TIMEOUT);

			InputStream is = fcpSocket.getInputStream();
			LineReadingInputStream lis = new LineReadingInputStream(is);
			OutputStream os = fcpSocket.getOutputStream();

			try
			{
				sfs.putSingle("Name", "AddRef");
				sfs.putSingle("ExpectedVersion", "2.0");
				fcpm = FCPMessage.create("ClientHello", sfs);
				fcpm.send(os);
				os.flush();

				String messageName = lis.readLine(128, 128, true);
				sfs = getMessage(lis);
				fcpm = FCPMessage.create(messageName, sfs);
				if ((fcpm == null) || !(fcpm instanceof NodeHelloMessage))
				{
					System.err.println("Not a valid FRED node!");
					System.exit(1);
				}
			}
			catch (MessageInvalidException me)
			{
				me.printStackTrace();
			}

			try
			{
				sfs = SimpleFieldSet.readFrom(reference, false, true);
				fcpm = FCPMessage.create(AddPeer.NAME, sfs);
				fcpm.send(os);
				os.flush();

				// TODO: We ought to do stricter checking!
				// FIXME: some checks even
			}
			catch (MessageInvalidException me)
			{
				System.err.println("Invalid reference file!" + me);
				me.printStackTrace();
			}

			lis.close();
			is.close();
			os.close();
			fcpSocket.close();
			System.out.println("That reference has been added");
		}
		catch (SocketException se)
		{
			System.err.println(se);
			se.printStackTrace();
			System.exit(1);
		}
		catch (IOException ioe)
		{
			System.err.println(ioe);
			ioe.printStackTrace();
			System.exit(2);
		}
		finally
		{
			try
			{
				Thread.sleep(CONST_SLEEP);
			}
			catch (InterruptedException e)
			{
			}
		}
	}

	/**
	 * 
	 * @param lis
	 * @return
	 */
	protected SimpleFieldSet getMessage(LineReadingInputStream lis)
	{
		SimpleFieldSet sfs = new SimpleFieldSet(true);
		try
		{
			while (lis.available() > 0)
			{
				String line = lis.readLine(128, 128, true);
				int index = line.indexOf('=');
				if (index == -1 || line.startsWith("End"))
					return sfs;
				sfs.putSingle(line.substring(0, index), line.substring(index + 1));
			}
		}
		catch (IOException e)
		{
			return sfs;
		}

		return sfs;
	}
}

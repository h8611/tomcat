/*
 *  Licensed to the Apache Software Foundation (ASF) under one or more
 *  contributor license agreements.  See the NOTICE file distributed with
 *  this work for additional information regarding copyright ownership.
 *  The ASF licenses this file to You under the Apache License, Version 2.0
 *  (the "License"); you may not use this file except in compliance with
 *  the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
package org.apache.coyote.http11;

import org.apache.coyote.InputBuffer;
import org.apache.coyote.Request;
import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;
import org.apache.tomcat.util.buf.ByteChunk;
import org.apache.tomcat.util.buf.MessageBytes;
import org.apache.tomcat.util.http.HeaderUtil;
import org.apache.tomcat.util.http.parser.HttpParser;
import org.apache.tomcat.util.net.AbstractEndpoint;
import org.apache.tomcat.util.net.SocketWrapper;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.net.Socket;

/**
 * Implementation of InputBuffer which provides HTTP request header parsing as
 * well as transfer decoding.
 *
 * @author <a href="mailto:remm@apache.org">Remy Maucherat</a>
 */
public class InternalInputBuffer extends AbstractInputBuffer<Socket> {

    private static final Log log = LogFactory.getLog(InternalInputBuffer.class);


    /**
     * Underlying input stream.
     */
    private InputStream inputStream;


    /**
     * Default constructor.
     */
    public InternalInputBuffer(Request request, int headerBufferSize,
            boolean rejectIllegalHeader, HttpParser httpParser) {

        this.request = request;
        headers = request.getMimeHeaders();

        buf = new byte[headerBufferSize];

        this.rejectIllegalHeaderName = rejectIllegalHeader;
        this.httpParser = httpParser;

        inputStreamInputBuffer = new InputStreamInputBuffer();

        filterLibrary = new InputFilter[0];
        activeFilters = new InputFilter[0];
        lastActiveFilter = -1;

        // 是否读取请求头的标志，这里为true，首次一定要读取请求头，后面每次请求过程中，会设置为false，处理完成又会设置true，以便下次请求使用
        parsingHeader = true;
        swallowInput = true;

    }


    /**
     * Read the request line. This function is meant to be used during the
     * HTTP request header parsing. Do NOT attempt to read the request body
     * using it.
     *
     * @throws IOException If an exception occurs during the underlying socket
     * read operations, or if the given buffer is not big enough to accommodate
     * the whole line.
     */
    @Override
    public boolean parseRequestLine(boolean useAvailableDataOnly)

        throws IOException {

        int start = 0;

        //
        // Skipping blank lines
        //

        do {

            // Read new bytes if needed
            if (pos >= lastValid) {
                if (!fill())
                    throw new EOFException(sm.getString("iib.eof.error"));
            }
            // Set the start time once we start reading data (even if it is
            // just skipping blank lines)
            if (request.getStartTime() < 0) {
                request.setStartTime(System.currentTimeMillis());
            }
            chr = buf[pos++];
        } while (chr == Constants.CR || chr == Constants.LF);

        pos--;

        // Mark the current buffer position
        start = pos;

        //
        // Reading the method name
        // Method name is a token
        //

        boolean space = false;

        while (!space) {

            // Read new bytes if needed
            if (pos >= lastValid) {
                if (!fill())
                    throw new EOFException(sm.getString("iib.eof.error"));
            }

            // Spec says method name is a token followed by a single SP but
            // also be tolerant of multiple SP and/or HT.
            if (buf[pos] == Constants.SP || buf[pos] == Constants.HT) {
                space = true;
                /**
                 * 设置调用方法，这里没有直接设置字符串，而是用了ByteChunk
                 * ByteChunk中包含一个字节数据类型的属性buff，此处的setBytes方法就是将buff指向Tomcat的缓存buf。然后start和end标记为
                 * 此处方法的后两个入参，也就是将请求方法在buf中标记了出来，但是没有转换成字符串，等到确实使用到的时候再使用ByteBuffer.wap方法
                 * 转换成字符串，且标记hasStrValue=true，如果再次获取就直接拿转换好的字符串，不用再次转换。效率考虑？牛逼！
                 * 因此，就算后面由于请求体过长，Tomcat重新开辟新的数组buf读取请求体。原buf也不会被GC，因为ByteChunk中的buff引用了原buf数组
                 * 什么时候原数组才会被GC？本次请求结束，request对象被GC后。。。
                 */
                request.method().setBytes(buf, start, pos - start);
            } else if (!HttpParser.isToken(buf[pos])) {
                String invalidMethodValue = parseInvalid(start, buf);
                throw new IllegalArgumentException(sm.getString("iib.invalidmethod", invalidMethodValue));
            }

            pos++;

        }

        // Spec says single SP but also be tolerant of multiple SP and/or HT
        while (space) {
            // Read new bytes if needed
            if (pos >= lastValid) {
                if (!fill())
                    throw new EOFException(sm.getString("iib.eof.error"));
            }
            if (buf[pos] == Constants.SP || buf[pos] == Constants.HT) {
                pos++;
            } else {
                space = false;
            }
        }

        // Mark the current buffer position
        start = pos;
        int end = 0;
        int questionPos = -1;

        //
        // Reading the URI
        //

        boolean eol = false;

        while (!space) {

            // Read new bytes if needed
            if (pos >= lastValid) {
                if (!fill())
                    throw new EOFException(sm.getString("iib.eof.error"));
            }

            if (buf[pos -1] == Constants.CR && buf[pos] != Constants.LF) {
                // CR not followed by LF so not an HTTP/0.9 request and
                // therefore invalid. Trigger error handling.
                // Avoid unknown protocol triggering an additional error
                request.protocol().setString(Constants.HTTP_11);
                String invalidRequestTarget = parseInvalid(start, buf);
                throw new IllegalArgumentException(sm.getString("iib.invalidRequestTarget", invalidRequestTarget));
            }

            // Spec says single SP but it also says be tolerant of HT
            if (buf[pos] == Constants.SP || buf[pos] == Constants.HT) {
                space = true;
                end = pos;
            } else if (buf[pos] == Constants.CR) {
                // HTTP/0.9 style request. CR is optional. LF is not.
            } else if (buf[pos] == Constants.LF) {
                // HTTP/0.9 style request
                // Stop this processing loop
                space = true;
                // Set blank protocol (indicates HTTP/0.9)
                request.protocol().setString("");
                // Skip the protocol processing
                eol = true;
                if (buf[pos - 1] == Constants.CR) {
                    end = pos - 1;
                } else {
                    end = pos;
                }
            } else if ((buf[pos] == Constants.QUESTION) && (questionPos == -1)) {
                questionPos = pos;
            } else if (questionPos != -1 && !httpParser.isQueryRelaxed(buf[pos])) {
                // %nn decoding will be checked at the point of decoding
                String invalidRequestTarget = parseInvalid(start, buf);
                throw new IllegalArgumentException(sm.getString("iib.invalidRequestTarget", invalidRequestTarget));
            } else if (httpParser.isNotRequestTargetRelaxed(buf[pos])) {
                // This is a general check that aims to catch problems early
                // Detailed checking of each part of the request target will
                // happen in AbstractHttp11Processor#prepareRequest()
                String invalidRequestTarget = parseInvalid(start, buf);
                throw new IllegalArgumentException(sm.getString("iib.invalidRequestTarget", invalidRequestTarget));
            }
            pos++;
        }
        request.unparsedURI().setBytes(buf, start, end - start);
        if (questionPos >= 0) {
            request.queryString().setBytes(buf, questionPos + 1,
                                           end - questionPos - 1);
            request.requestURI().setBytes(buf, start, questionPos - start);
        } else {
            request.requestURI().setBytes(buf, start, end - start);
        }

        // Spec says single SP but also says be tolerant of multiple SP and/or HT
        while (space && !eol) {
            // Read new bytes if needed
            if (pos >= lastValid) {
                if (!fill())
                    throw new EOFException(sm.getString("iib.eof.error"));
            }
            if (buf[pos] == Constants.SP || buf[pos] == Constants.HT) {
                pos++;
            } else {
                space = false;
            }
        }

        // Mark the current buffer position
        start = pos;
        end = 0;

        //
        // Reading the protocol
        // Protocol is always "HTTP/" DIGIT "." DIGIT
        //
        while (!eol) {

            // Read new bytes if needed
            if (pos >= lastValid) {
                if (!fill())
                    throw new EOFException(sm.getString("iib.eof.error"));
            }

            if (buf[pos] == Constants.CR) {
                // Possible end of request line. Need LF next.
            } else if (buf[pos - 1] == Constants.CR && buf[pos] == Constants.LF) {
                end = pos - 1;
                eol = true;
            } else if (!HttpParser.isHttpProtocol(buf[pos])) {
                String invalidProtocol = parseInvalid(start, buf);
                throw new IllegalArgumentException(sm.getString("iib.invalidHttpProtocol", invalidProtocol));
            }

            pos++;

        }

        if ((end - start) > 0) {
            request.protocol().setBytes(buf, start, end - start);
        }

        if (request.protocol().isNull()) {
            throw new IllegalArgumentException(sm.getString("iib.invalidHttpProtocol"));
        }

        return true;
    }


    /**
     * Parse the HTTP headers.
     */
    @Override
    public boolean parseHeaders()
        throws IOException {
        if (!parsingHeader) {
            throw new IllegalStateException(
                    sm.getString("iib.parseheaders.ise.error"));
        }

        while (parseHeader()) {
            // Loop until we run out of headers
        }

        parsingHeader = false;
        end = pos;
        return true;
    }


    /**
     * Parse an HTTP header.
     *
     * @return false after reading a blank line (which indicates that the
     * HTTP header parsing is done
     */
    @SuppressWarnings("null") // headerValue cannot be null
    private boolean parseHeader() throws IOException {

        while (true) {

            // Read new bytes if needed
            if (pos >= lastValid) {
                if (!fill())
                    throw new EOFException(sm.getString("iib.eof.error"));
            }

            prevChr = chr;
            chr = buf[pos];

            if (chr == Constants.CR && prevChr != Constants.CR) {
                // Possible start of CRLF - process the next byte.
            } else if (prevChr == Constants.CR && chr == Constants.LF) {
                pos++;
                return false;
            } else {
                if (prevChr == Constants.CR) {
                    // Must have read two bytes (first was CR, second was not LF)
                    pos--;
                }
                break;
            }

            pos++;
        }

        // Mark the current buffer position
        int start = pos;
        int lineStart = start;

        //
        // Reading the header name
        // Header name is always US-ASCII
        //

        boolean colon = false;
        MessageBytes headerValue = null;

        while (!colon) {

            // Read new bytes if needed
            if (pos >= lastValid) {
                if (!fill())
                    throw new EOFException(sm.getString("iib.eof.error"));
            }

            if (buf[pos] == Constants.COLON) {
                colon = true;
                headerValue = headers.addValue(buf, start, pos - start);
            } else if (!HttpParser.isToken(buf[pos])) {
                // Non-token characters are illegal in header names
                // Parsing continues so the error can be reported in context
                // skipLine() will handle the error
                skipLine(lineStart, start);
                return true;
            }

            chr = buf[pos];
            if ((chr >= Constants.A) && (chr <= Constants.Z)) {
                buf[pos] = (byte) (chr - Constants.LC_OFFSET);
            }

            pos++;

        }

        // Mark the current buffer position
        start = pos;
        int realPos = pos;

        //
        // Reading the header value (which can be spanned over multiple lines)
        //

        boolean eol = false;
        boolean validLine = true;

        while (validLine) {

            boolean space = true;

            // Skipping spaces
            while (space) {

                // Read new bytes if needed
                if (pos >= lastValid) {
                    if (!fill())
                        throw new EOFException(sm.getString("iib.eof.error"));
                }

                if ((buf[pos] == Constants.SP) || (buf[pos] == Constants.HT)) {
                    pos++;
                } else {
                    space = false;
                }

            }

            int lastSignificantChar = realPos;

            // Reading bytes until the end of the line
            while (!eol) {

                // Read new bytes if needed
                if (pos >= lastValid) {
                    if (!fill())
                        throw new EOFException(sm.getString("iib.eof.error"));
                }

                prevChr = chr;
                chr = buf[pos];
                if (chr == Constants.CR) {
                    // Possible start of CRLF - process the next byte.
                } else if (prevChr == Constants.CR && chr == Constants.LF) {
                    eol = true;
                } else if (prevChr == Constants.CR) {
                    // Invalid value
                    // Delete the header (it will be the most recent one)
                    headers.removeHeader(headers.size() - 1);
                    skipLine(lineStart, start);
                    return true;
                } else if (chr != Constants.HT && HttpParser.isControl(chr)) {
                    // Invalid value
                    // Delete the header (it will be the most recent one)
                    headers.removeHeader(headers.size() - 1);
                    skipLine(lineStart, start);
                    return true;
                } else if (chr == Constants.SP) {
                    buf[realPos] = chr;
                    realPos++;
                } else {
                    buf[realPos] = chr;
                    realPos++;
                    lastSignificantChar = realPos;
                }

                pos++;

            }

            realPos = lastSignificantChar;

            // Checking the first character of the new line. If the character
            // is a LWS, then it's a multiline header

            // Read new bytes if needed
            if (pos >= lastValid) {
                if (!fill())
                    throw new EOFException(sm.getString("iib.eof.error"));
            }

            byte peek = buf[pos];
            if (peek != Constants.SP && peek != Constants.HT) {
                validLine = false;
            } else {
                eol = false;
                // Copying one extra space in the buffer (since there must
                // be at least one space inserted between the lines)
                buf[realPos] = peek;
                realPos++;
            }

        }

        // Set the header value
        headerValue.setBytes(buf, start, realPos - start);

        return true;

    }


    @Override
    public void recycle() {
        super.recycle();
        inputStream = null;
    }


    // ------------------------------------------------------ Protected Methods


    @Override
    protected void init(SocketWrapper<Socket> socketWrapper,
            AbstractEndpoint<Socket> endpoint) throws IOException {
        inputStream = socketWrapper.getSocket().getInputStream();
    }



    private void skipLine(int lineStart, int start) throws IOException {
        boolean eol = false;
        int lastRealByte = start;
        if (pos - 1 > start) {
            lastRealByte = pos - 1;
        }

        while (!eol) {

            // Read new bytes if needed
            if (pos >= lastValid) {
                if (!fill())
                    throw new EOFException(sm.getString("iib.eof.error"));
            }

            prevChr = chr;
            chr = buf[pos];

            if (chr == Constants.CR) {
                // Skip
            } else if (prevChr == Constants.CR && chr == Constants.LF) {
                eol = true;
            } else {
                lastRealByte = pos;
            }
            pos++;
        }

        if (rejectIllegalHeaderName || log.isDebugEnabled()) {
            String message = sm.getString("iib.invalidheader", HeaderUtil.toPrintableString(
                    buf, lineStart, lastRealByte - lineStart + 1));
            if (rejectIllegalHeaderName) {
                throw new IllegalArgumentException(message);
            }
            log.debug(message);
        }
    }

    /**
     * Fill the internal buffer using data from the underlying input stream.
     *
     * @return false if at end of stream
     */
    protected boolean fill() throws IOException {
        return fill(true);
    }

    @Override
    protected boolean fill(boolean block) throws IOException {

        int nRead = 0;

        /**
         * 这个核心就是读取socket中数据到缓冲区buf中，循环读取，2种情况
         * 1、请求行和请求头：不能超过缓冲区大小(默认8kb)，如果超过，则抛异常，读完后将parsingHeader设置为false
         * 2、请求行：没有任何大小限制，循环读取，如果剩下的少于4500个字节，则会重新创建buf数组，从头开始读取，直到读完位置，注意！buf原先引用的数组们，等待GC
         */
        if (parsingHeader) {

            /**
             * 从socket中读取数据大于tomcat中缓冲区buf的长度，直接抛异常,这里有两点
             * 1、这个就是我们很多时候很多人说的，get请求url不能过长的原因，其实是header和url等总大小不能超过8kb
             * 2、这里的buf非常总要，它是InternalInputBuffer的属性，是一个字节数据，用户暂存从socket中读取的数据，比如：请求行，请求头、请求体
             */
            if (lastValid == buf.length) {
                throw new IllegalArgumentException
                    (sm.getString("iib.requestheadertoolarge.error"));
            }

            // 将socket中的数据读到缓冲区buf中，注意！这里就是BIO之所以难懂的关键所在，它会阻塞！
            // 这个方法会阻塞，如果没有数据可读，则会一直阻塞，有数据，则移动lastValid位置
            nRead = inputStream.read(buf, pos, buf.length - lastValid);
            if (nRead > 0) {
                lastValid = pos + nRead;
            }

        } else {

            if (buf.length - end < 4500) {
                // In this case, the request header was really large, so we allocate a
                // brand new one; the old one will get GCed when subsequent requests
                // clear all references
                buf = new byte[buf.length];
                end = 0;
            }
            pos = end;
            lastValid = pos;
            nRead = inputStream.read(buf, pos, buf.length - lastValid);
            if (nRead > 0) {
                lastValid = pos + nRead;
            }

        }
        // 原则上这个方法要么阻塞着，要么就返回true
        return (nRead > 0);

    }


    // ------------------------------------- InputStreamInputBuffer Inner Class


    /**
     * This class is an input buffer which will read its data from an input
     * stream.
     */
    protected class InputStreamInputBuffer
        implements InputBuffer {


        /**
         * Read bytes into the specified chunk.
         */
        @Override
        public int doRead(ByteChunk chunk, Request req )
            throws IOException {

            if (pos >= lastValid) {
                if (!fill())
                    return -1;
            }

            int length = lastValid - pos;
            chunk.setBytes(buf, pos, length);
            pos = lastValid;

            return (length);
        }
    }
}

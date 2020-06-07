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
    /**
     * 读取请求行方法
     * 请求行格式如下：
     * ========================================
     * 请求方法 空格 URL 空格 协议版本 回车换行
     * ========================================
     * @param useAvailableDataOnly
     * @return
     * @throws IOException
     */
    @Override
    public boolean parseRequestLine(boolean useAvailableDataOnly)

        throws IOException {

        int start = 0;

        //
        // Skipping blank lines
        //

        /**
         * 过滤掉回车(CR)换行(LF)符，确定start位置
         */
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
            /**
             * chr记录第一个非CRLF字节，后面读取请求头的时候用到
             */
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

        /**
         * 读取HTT请求方法：get/post/put....
         */
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
                 * 设置HTTP请求方法，这里没有直接设置字符串，而是用了字节块ByteChunk
                 * ByteChunk中包含一个字节数据类型的属性buff，此处的setBytes方法就是将buff指向Tomcat的缓存buf。然后start和end标记为
                 * 此处方法的后两个入参，也就是将请求方法在buf中标记了出来，但是没有转换成字符串，等到使用的时候再使用ByteBuffer.wap方法
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
        /**
         * 过滤请求方法后面的空格(SP或者HT)
         */
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

        /**
         * 读取URL
         */
        while (!space) {

            // Read new bytes if needed
            if (pos >= lastValid) {
                if (!fill())
                    throw new EOFException(sm.getString("iib.eof.error"));
            }

            /**
             * CR后面没有LF，不是HTTP0.9，抛异常
             */
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
                /**
                 * 遇到空格(SP或者HT)，URL读取结束
                 */
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
        /**
         * 读取HTTP URL
         */
        request.unparsedURI().setBytes(buf, start, end - start);
        if (questionPos >= 0) {
            /**
             * 当有请求入参的时候
             * 读取入参字符串
             * 读取URI
             */
            request.queryString().setBytes(buf, questionPos + 1,
                                           end - questionPos - 1);
            request.requestURI().setBytes(buf, start, questionPos - start);
        } else {
            /**
             * 没有请求入参的时候，直接读取URI
             */
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
        /**
         * 读取HTTP协议版本
         */
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

        /**
         * 字节块标记协议版本
         */
        if ((end - start) > 0) {
            request.protocol().setBytes(buf, start, end - start);
        }

        /**
         * 如果没有协议版本，无法处理请求，抛异常
         */
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
        /**
         * 请求行和请求头读取的标志，如果不是请求行和请求头，进入此方法，抛异常
         */
        if (!parsingHeader) {
            throw new IllegalStateException(
                    sm.getString("iib.parseheaders.ise.error"));
        }

        /**
         * 读取请求头，循环执行，每次循环读取请求头的一个key:value对
         */
        while (parseHeader()) {
            // Loop until we run out of headers
        }

        /**
         * 请求头读取完毕，标志变为false，end=pos,标志此处是请求行和请求头读取完毕的位置
         */
        parsingHeader = false;
        end = pos;
        return true;
    }


    /**
     * 读取请求头信息，注意：每次调用该方法，完成一个键值对读取，也即下面格式中的一行请求头
     * 请求头格式如下
     * ===================================
     * key:空格(SP)value回车(CR)换行(LF)
     * ...
     * key:空格(SP)value回车(CR)换行(LF)
     * 回车(CR)换行(LF)
     * ===================================
     *
     * Parse an HTTP header.
     *
     * @return false after reading a blank line (which indicates that the
     * HTTP header parsing is done
     */
    @SuppressWarnings("null") // headerValue cannot be null
    private boolean parseHeader() throws IOException {

        /**
         * 此循环主要是在每行请求头信息开始前，确定首字节的位置
         */
        while (true) {

            // Read new bytes if needed
            /**
             * Tomcat缓存buf中没有带读取数据，重新从操作系统读取一批
             */
            if (pos >= lastValid) {
                if (!fill())
                    throw new EOFException(sm.getString("iib.eof.error"));
            }

            /**
             * 这里的chr最开始是在读取请求行时赋值，赋予它请求行第一个非空格字节
             */
            prevChr = chr;
            chr = buf[pos];

            /**
             * 首位置是回车符(CR)，有2种情况：
             * 1、CR+(~LF) 首次先往后移动一个位置，试探第二个位置是否是LF，如果是则进入情况2；如果不是,则回退pos。key首字节可以是CR，但第2个字节不能是LF，因为行CRLF是请求头结束标志
             * 2、CR+LF 请求头结束标志，直接结束请求头读取
             * 首位置不是CR，直接结束循环，开始读取key
             */
            if (chr == Constants.CR && prevChr != Constants.CR) {
                /**
                 * 每次while循环首次进入这个if分支preChr都不是CR，如果当前位置pos是CR，则往后移动一位，根据后一位情况决定后续操作
                 * 如果后一位是LF，直接直接请求头读取
                 * 如果后一位不是LF,pos回退一位，用作key。
                 */
                // Possible start of CRLF - process the next byte.
            } else if (prevChr == Constants.CR && chr == Constants.LF) {
                /**
                 * 请求头结束,注意是请求头结束，不是当前键值对结束，请求头结束标志：没有任何其他数据，直接CRLF
                 */
                pos++;
                return false;
            } else {
                /**
                 * 如果当前行的首字节不是CR，直接break，开始读取key
                 * 如果当前行首字节是CR，但是第二字节不是LF，pos回退1位，开始读取key
                 */
                if (prevChr == Constants.CR) {
                    // Must have read two bytes (first was CR, second was not LF)
                    pos--;
                }
                break;
            }

            pos++;
        }

        // Mark the current buffer position
        /**
         * 标记当前键值对行开始位置
         */
        int start = pos;
        int lineStart = start;

        //
        // Reading the header name
        // Header name is always US-ASCII
        //

        /**
         * colon标记冒号的位置
         */
        boolean colon = false;
        MessageBytes headerValue = null;

        /**
         * 读取key，直到当前字节是冒号(:)跳出循环，pos指向冒号后一个字节
         */
        while (!colon) {

            // Read new bytes if needed
            /**
             * 获取缓冲区数据
             */
            if (pos >= lastValid) {
                if (!fill())
                    throw new EOFException(sm.getString("iib.eof.error"));
            }


            if (buf[pos] == Constants.COLON) {
                /**
                 * 当前字节是冒号，colon=true,当前循环执行完后，结束循环
                 * 在Tomcat缓冲区buf字节数组中标记出头信息的名称key：
                 * 每个key:value对中有2个MessageBytes对象，每个MessageBytes对象中都有字节块ByteChunk，用来标记buf中的字节段
                 */
                colon = true;
                headerValue = headers.addValue(buf, start, pos - start);
            } else if (!HttpParser.isToken(buf[pos])) {
                // Non-token characters are illegal in header names
                // Parsing continues so the error can be reported in context
                // skipLine() will handle the error
                /**
                 * 非普通字符，比如：(,?,:等，跳过这行
                 */
                skipLine(lineStart, start);
                return true;
            }

            /**
             * 大写字符转换成小写字符，chr记录key中最后一个有效字节
             */
            chr = buf[pos];
            if ((chr >= Constants.A) && (chr <= Constants.Z)) {
                buf[pos] = (byte) (chr - Constants.LC_OFFSET);
            }

            /**
             * 下标自增，继续下次循环
             */
            pos++;

        }

        // Mark the current buffer positio
        /**
         * 重置start，开始读取请求头值value
         */
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
            /**
             * 跳过空格(SP)和制表符(HT)
             */
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
            /**
             *
             */
            while (!eol) {

                // Read new bytes if needed
                if (pos >= lastValid) {
                    if (!fill())
                        throw new EOFException(sm.getString("iib.eof.error"));
                }

                /**
                 * prevChr首次为chr=:,之后为上一次循环的chr
                 * chr为当前pos位置的字节
                 */
                prevChr = chr;
                chr = buf[pos];
                if (chr == Constants.CR) {
                    /**
                     * 当前字节是回车符，直接下次循环，看下个字节是否是LF
                     */
                    // Possible start of CRLF - process the next byte.
                } else if (prevChr == Constants.CR && chr == Constants.LF) {
                    /**
                     * 当前字节是LF,前一个字节是CR，请求头当前key:value行读取结束
                     */
                    eol = true;
                } else if (prevChr == Constants.CR) {
                    /**
                     * 如果前一字节是CR，当前位置字节不是LF，则本key:value对无效，删除！
                     * 直接返回true，读取下一个key:value对
                     */
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
                    /**
                     * 当前位置空格，位置后移一位
                     */
                    buf[realPos] = chr;
                    realPos++;
                } else {
                    /**
                     * 当前位置常规字符，位置后移一位，标记最后字符
                     */
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

            /**
             * 特殊逻辑：
             * 当前key:value对读取完后，
             * 如果紧接着的是SP(空格)或则HT(制表符),表示当前value读取并未结束，是多行的，将eol=false，继续读取，直到CRLF.
             * 如果紧接着不是SP和HT，那vaLine=false,跳出循环，value读取完毕
             */
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
        /**
         * 使用新的字节块BytChunk标记当前key:value对的value
         */
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
            /**
             * parsingHeader==false，请求行和请求头已经读取完毕，开始读取请求体
             */

            if (buf.length - end < 4500) {
                // In this case, the request header was really large, so we allocate a
                // brand new one; the old one will get GCed when subsequent requests
                // clear all references
                /**
                 * 如果Tomcat缓存区buf读取完请求行和请求头后，剩余长度不足4500(可配置)，新创建一个字节数组buf用于读取请求体
                 * 为什么要这么做，应该是考虑到如果剩余的数据长度较小，每次从操作系统缓存区读取的字节就比较少，读取次数就比较多？
                 * 注意，buf原先指向的字节数据会白GC么？应该不会，因为请求行和请求头有许多字节块(ByteChunk)指向了旧字节数据。
                 * 什么时候才会被GC？应该是一起request处理完毕后。
                 */
                buf = new byte[buf.length];
                end = 0;
            }
            /**
             * 这里的end是请求头数据的后一位，从这里开始读取请求体数据。
             * 从操作系统读取数据到buf中，下标pos开始，lastValid结束
             * 注意：这里每次读取请求体数据的时候都会把pos重置为end(请求头数据的后一位)!!!!!
             * 表示什么？
             * 请求体数据每一次从操作系统缓存中读取到buf，然后读取到程序员自己的数组后，在下次再次从操作系统读取数据到buf时，就会把之前读取的请求体数据覆盖掉
             * 也就是从end位置开始，后面的数据都只能读取一次，这个很重要！！！
             * 为什么这么做？我的理解是因为请求体数据可以很大，为了单个请求不占用太大内存，所以设计成了覆盖的模式，真是秒啊！
             */
            pos = end;
            lastValid = pos;

            /**
             * 原则上这个方法要么阻塞着，要么nRead>0
             */
            nRead = inputStream.read(buf, pos, buf.length - lastValid);
            if (nRead > 0) {
                lastValid = pos + nRead;
            }

        }

        /**
         * 注意，这里不出意外，只能返回true
          */
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

            /**
             * pos>=lastValid，表示无数据可解析，下面两种情况
             * 1、单次读取请求体
             * 2、多次循环读取
             * 以上情况都会从操作系统读取数据到Tomcat缓存区buf中
             */
            if (pos >= lastValid) {
                if (!fill())
                    return -1;
            }

            /**
             * 用字节块chunk标记当前读取的请求数据，从pos到lastValid
             * 同时将pos=lastValid，为了下次能够从操作系统再次读取数据
             */
            int length = lastValid - pos;
            chunk.setBytes(buf, pos, length);
            pos = lastValid;

            return (length);
        }
    }
}

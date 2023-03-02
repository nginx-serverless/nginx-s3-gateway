/*
 *  Copyright 2023 F5, Inc.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

/**
 * Flag indicating debug mode operation. If true, additional information
 * about signature generation will be logged.
 * @type {boolean}
 */
const DEBUG = parseBoolean(process.env['S3_DEBUG']);


/**
 * Parses a string to and returns a boolean value based on its value. If the
 * string can't be parsed, this method returns false.
 *
 * @param string {*} value representing a boolean
 * @returns {boolean} boolean value of string
 * @private
 */
function parseBoolean(string) {
    switch(string) {
        case "TRUE":
        case "true":
        case "True":
        case "YES":
        case "yes":
        case "Yes":
        case "1":
            return true;
        default:
            return false;
    }
}

/**
 * Outputs a log message to the request logger if debug messages are enabled.
 *
 * @param r {Request} HTTP request object
 * @param msg {string} message to log
 * @private
 */
function debug_log(r, msg) {
    if (DEBUG && "log" in r) {
        r.log(msg);
    }
}

/**
 * Pads the supplied number with leading zeros.
 *
 * @param num {number|string} number to pad
 * @param size number of leading zeros to pad
 * @returns {string} a string with leading zeros
 * @private
 */
function padWithLeadingZeros(num, size) {
    const s = "0" + num;
    return s.substr(s.length-size);
}

/**
 * Formats a timestamp into a date string in the format 'YYYYMMDD'.
 *
 * @param timestamp {Date} timestamp
 * @returns {string} a formatted date string based on the input timestamp
 * @private
 */
function getEightDigitDate(timestamp) {
    const year = timestamp.getUTCFullYear();
    const month = timestamp.getUTCMonth() + 1;
    const day = timestamp.getUTCDate();

    return ''.concat(utils.padWithLeadingZeros(year, 4),
        utils.padWithLeadingZeros(month,2),
        utils.padWithLeadingZeros(day,2));
}

/**
 * Creates a string in the ISO601 date format (YYYYMMDD'T'HHMMSS'Z') based on
 * the supplied timestamp and date. The date is not extracted from the timestamp
 * because that operation is already done once during the signing process.
 *
 * @param timestamp {Date} timestamp to extract date from
 * @param eightDigitDate {string} 'YYYYMMDD' format date string that was already extracted from timestamp
 * @returns {string} string in the format of YYYYMMDD'T'HHMMSS'Z'
 * @private
 */
function getAmzDatetime(timestamp, eightDigitDate) {
    const hours = timestamp.getUTCHours();
    const minutes = timestamp.getUTCMinutes();
    const seconds = timestamp.getUTCSeconds();

    return ''.concat(
        eightDigitDate,
        'T', utils.padWithLeadingZeros(hours, 2),
        utils.padWithLeadingZeros(minutes, 2),
        utils.padWithLeadingZeros(seconds, 2),
        'Z');
}

export default {
    debug_log,
    getAmzDatetime,
    getEightDigitDate,
    padWithLeadingZeros,
    parseBoolean
}

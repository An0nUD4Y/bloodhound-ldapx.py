####################
#
# Copyright (c) 2018 Fox-IT
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
####################

import logging
import codecs
import json
import os

MAX_ENTRIES = 40000


def _open_partial(final_name):
    partial = final_name + '.partial'
    handle = codecs.open(partial, 'w', 'utf-8')
    return handle, partial


def _publish(handle, partial, final_name):
    """
    Flush the footer and only then replace the real output file.
    """
    handle.flush()
    try:
        os.fsync(handle.fileno())
    except (OSError, AttributeError):
        pass
    handle.close()
    os.replace(partial, final_name)

class OutputWorker(object):
    @staticmethod
    def drain_queue(result_q):
        """
            Consume and acknowledge queue items up to and including the None sentinel,
            so producers waiting on result_q.join() are not blocked forever.
        """
        while True:
            obj = result_q.get()
            result_q.task_done()
            if obj is None:
                break

    @staticmethod
    def write_worker(result_q, computers_filename):
        """
            Worker to write the results from the results_q to the given files.
        """

        try:
            computers_out, partial = _open_partial(computers_filename)
        except Exception:
            logging.warning('Could not write file: %s', computers_filename)
            OutputWorker.drain_queue(result_q)
            return False
        current_final = computers_filename
        filenumber = 0

        # If the logging level is DEBUG, we ident the objects
        if logging.getLogger().getEffectiveLevel() == logging.DEBUG:
            indent_level = 1
        else:
            indent_level = None

        # Write start of the json file
        computers_out.write('{"data":[')
        num_computers = 0
        current_num_computers = 0

        while True:
            obj = result_q.get()

            if obj is None:
                logging.debug('Write worker obtained a None value, exiting')
                break

            objtype, data = obj
            if objtype == 'computer':
                if current_num_computers != 0:
                    computers_out.write(',')
                try:
                    encoded_computer = json.dumps(data, indent=indent_level)
                    computers_out.write(encoded_computer)
                except TypeError:
                    logging.error('Data error {0}, could not convert data to json'.format(repr(data)))
                    computers_out.write('{}')
                num_computers += 1
                current_num_computers += 1
            else:
                logging.warning("Type is %s this should not happen", objtype)

            result_q.task_done()
            # Loop file if it gets too big
            if num_computers % MAX_ENTRIES == 0 and num_computers > 0:
                logging.debug('Rotating output file %s', current_final)
                computers_out.write('],"meta":{"methods":0,"type":"computers","count":%d, "version":6}}' % current_num_computers)
                _publish(computers_out, partial, current_final)
                filenumber += 1
                current_final = computers_filename.replace('.json', '_%02d.json' % filenumber)
                computers_out, partial = _open_partial(current_final)
                current_num_computers = 0
                computers_out.write('{"data":[')


        logging.debug('Write worker is done, closing files')
        # Write metadata manually
        wrote = False
        try:
            computers_out.write('],"meta":{"methods":0,"type":"computers","count":%d, "version":6}}' % current_num_computers)
            _publish(computers_out, partial, current_final)
            logging.info('Found %d computers', num_computers)
            wrote = True
        finally:
            result_q.task_done()
        return wrote

    @staticmethod
    def membership_write_worker(result_q, enumtype, filename):
        """
            Worker to write the results from the results_q to the given file.
            This is for both users and groups
        """
        try:
            membership_out, partial = _open_partial(filename)
            filenumber = 0
        except Exception:
            logging.warning('Could not write file: %s', filename)
            OutputWorker.drain_queue(result_q)
            return False
        current_final = filename

        # If the logging level is DEBUG, we ident the objects
        if logging.getLogger().getEffectiveLevel() == logging.DEBUG:
            indent_level = 1
        else:
            indent_level = None

        # Write start of the json file
        membership_out.write('{"data":[')
        num_members = 0
        current_num_members = 0
        while True:
            data = result_q.get()

            if data is None:
                break

            if current_num_members != 0:
                membership_out.write(',')
            try:
                encoded_member = json.dumps(data, indent=indent_level)
                membership_out.write(encoded_member)
            except TypeError:
                logging.error('Data error {0}, could not convert data to json'.format(repr(data)))
                membership_out.write('{}')
            num_members += 1
            current_num_members += 1

            result_q.task_done()
            # Loop file if it gets too big
            if num_members % MAX_ENTRIES == 0 and num_members > 0:
                logging.debug('Rotating output file %s', current_final)
                membership_out.write('],"meta":{"methods":0,"type":"%s","count":%d, "version":6}}' % (enumtype, current_num_members))
                _publish(membership_out, partial, current_final)
                filenumber += 1
                current_final = filename.replace('.json', '_%02d.json' % filenumber)
                membership_out, partial = _open_partial(current_final)
                current_num_members = 0
                membership_out.write('{"data":[')

        # Write metadata manually, then publish the file.
        wrote = False
        try:
            membership_out.write('],"meta":{"methods":0,"type":"%s","count":%d, "version":6}}' % (enumtype, current_num_members))
            _publish(membership_out, partial, current_final)
            logging.info('Found %d %s', num_members, enumtype)
            wrote = True
        finally:
            result_q.task_done()
        return wrote

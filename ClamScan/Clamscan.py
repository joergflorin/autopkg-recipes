#!/usr/bin/env python
#
# Copyright 2015 Joerg Florin
#
# Scans downloads with clamav

import os, subprocess
from autopkglib import Processor, ProcessorError

__all__ = ["ClamScan"]


class ClamScan(Processor):
    """This processor scans downloads with clamav."""
    description = __doc__
    input_variables = {
        "pathname": {
            "required": False,
            "description":
                "Pathname of downloaded artifact."
        }
    }
    output_variables = {
    }

    def main(self):
        try:
	    if "pathname" in self.env:
	        self.output("Scan for viruses in %s." % self.env["pathname"])
	        retcode = subprocess.call(["clamscan", "--no-summary", self.env["pathname"]])
	        if retcode == 1:
	            raise BaseException("download %s is infected by viruses!" % self.env["pathname"])
	        elif retcode != 0:
		    raise BaseException("error %s calling clamscan" % retcode)
            else:
		self.output("No pathname set to scan")
        except BaseException as err:
            # handle unexpected errors here
            raise ProcessorError(err)

if __name__ == "__main__":
    PROCESSOR = ClamScan()
    PROCESSOR.execute_shell()

/* Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "visit_counter.h"
#include <cstdint>
#include <iostream>
#include <map>

IpVisitCounter::IpVisitCounter() { enabled = false; }

uint32_t IpVisitCounter::getCount(uint64_t ip) {
  if (enabled) {
    std::map<uint64_t, uint32_t>::iterator it = ipVisitCountMap.find(ip);

    if (it == ipVisitCountMap.end()) {
      return 0;
    } else {
      return it->second;
    }
  } else {
    return 0;
  }
}

void IpVisitCounter::incrementCount(uint64_t ip) {
  if (enabled) {
    std::map<uint64_t, uint32_t>::iterator it = ipVisitCountMap.find(ip);

    if (it == ipVisitCountMap.end()) {
      ipVisitCountMap.insert(std::pair<uint64_t, uint32_t>(ip, 1));
    } else {
      uint32_t x = it->second + 1;
      it->second = x;
    }
  }
}

void IpVisitCounter::enable(void) { enabled = true; }

void IpVisitCounter::disable(void) { enabled = false; }

void IpVisitCounter::reset(void) { ipVisitCountMap.clear(); }

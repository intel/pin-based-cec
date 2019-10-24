/* Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __VISIT_COUNTER_H__
#define __VISIT_COUNTER_H__

#include <cstdint>
#include <map>

class IpVisitCounter {
 public:
  IpVisitCounter();
  uint32_t getCount(uint64_t ip);
  void incrementCount(uint64_t ip);
  void enable(void);
  void disable(void);
  void reset(void);

 private:
  bool enabled;
  std::map<uint64_t, uint32_t> ipVisitCountMap;
};

#endif

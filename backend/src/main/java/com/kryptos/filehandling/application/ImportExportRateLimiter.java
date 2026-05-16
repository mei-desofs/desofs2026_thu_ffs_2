package com.kryptos.filehandling.application;

import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.Instant;
import java.util.Deque;
import java.util.Iterator;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedDeque;

@Component
public class ImportExportRateLimiter {

  /** Window length used for both endpoints. */
  private static final Duration WINDOW = Duration.ofMinutes(1);
  /** Per-user budget per window for export. */
  private static final int EXPORT_BUDGET = 5;
  /** Per-user budget per window for import. */
  private static final int IMPORT_BUDGET = 5;

  private final ConcurrentHashMap<String, Deque<Instant>> exportHits = new ConcurrentHashMap<>();
  private final ConcurrentHashMap<String, Deque<Instant>> importHits = new ConcurrentHashMap<>();

  public boolean tryAcquireExport(String principal) {
    return tryAcquire(exportHits, principal, EXPORT_BUDGET);
  }

  public boolean tryAcquireImport(String principal) {
    return tryAcquire(importHits, principal, IMPORT_BUDGET);
  }

  public void resetAll() {
    exportHits.clear();
    importHits.clear();
  }

  private boolean tryAcquire(ConcurrentHashMap<String, Deque<Instant>> table,
      String principal, int budget) {
    if (principal == null)
      return false;
    Deque<Instant> hits = table.computeIfAbsent(principal, k -> new ConcurrentLinkedDeque<>());
    Instant now = Instant.now();
    // Drop entries that fell out of the window.
    synchronized (hits) {
      Iterator<Instant> it = hits.iterator();
      while (it.hasNext()) {
        if (Duration.between(it.next(), now).compareTo(WINDOW) > 0) {
          it.remove();
        } else {
          break;
        }
      }
      if (hits.size() >= budget) {
        return false;
      }
      hits.addLast(now);
      return true;
    }
  }
}

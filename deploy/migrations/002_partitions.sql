-- deploy/migrations/002_partitions.sql — daily partitions for the next 30 days
-- plus a DEFAULT partition on each range-partitioned table (overflow safety).
-- Partition names follow raw_events_y2026mmdd / normalized_events_y2026mmdd.
DO $$
DECLARE
  d date;
BEGIN
  FOR d IN SELECT generate_series(now()::date, now()::date + 30, '1 day')
  LOOP
    EXECUTE format(
      'CREATE TABLE IF NOT EXISTS %I PARTITION OF raw_events FOR VALUES FROM (%L) TO (%L)',
      'raw_events_y' || to_char(d, 'YYYYMMDD'), d, d + 1);
    EXECUTE format(
      'CREATE TABLE IF NOT EXISTS %I PARTITION OF normalized_events FOR VALUES FROM (%L) TO (%L)',
      'normalized_events_y' || to_char(d, 'YYYYMMDD'), d, d + 1);
  END LOOP;

  EXECUTE 'CREATE TABLE IF NOT EXISTS raw_events_default PARTITION OF raw_events DEFAULT';
  EXECUTE 'CREATE TABLE IF NOT EXISTS normalized_events_default PARTITION OF normalized_events DEFAULT';
END $$;

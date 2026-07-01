# Structured queries

Run `fbm categorize` after sync to rebuild the derived query layer.

## Axes

Thread axes:

- `source.folder`
- `thread.archive`
- `thread.kind`
- `thread.history`
- `participants.size`
- `volume.messages`
- `time.activity`

Message axes:

- `message.kind`
- `message.text`
- `message.attachment`
- `message.reactions`
- `message.mentions`
- `sender.scope`
- `volume.body`
- `time.sent`

## Examples

```sql
-- Safe aggregate counts.
SELECT scope, axis, path, item_count
FROM v_category_counts
ORDER BY item_count DESC;

-- Count attachment classes.
SELECT path, item_count
FROM v_category_counts
WHERE scope = 'message' AND axis = 'message.attachment'
ORDER BY item_count DESC;

-- Message IDs for photo messages in March 2024.
SELECT mc.message_id
FROM message_categories mc
JOIN message_dimensions md USING(message_id)
WHERE mc.axis = 'message.attachment'
  AND mc.path = 'attachment/photo'
  AND md.sent_year = 2024
  AND md.sent_month = 3;

-- Complete large group threads.
SELECT thread_id, stored_message_count
FROM thread_dimensions
WHERE thread_kind = 'group'
  AND history_state = 'complete'
  AND volume_bucket = '1000_plus';

-- Taxonomy children under a month.
SELECT axis, path, parent_path, depth
FROM category_nodes
WHERE axis = 'time.sent'
  AND parent_path = 'time/2024/03'
ORDER BY path;
```

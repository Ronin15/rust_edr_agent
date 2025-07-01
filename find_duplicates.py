#!/usr/bin/env python3
"""
Script to find duplicate and redundant events in EDR agent data.
This script analyzes event files to identify:
1. Exact duplicates (same event ID)
2. Near-duplicates (same content but different IDs)
3. Redundant events (similar events that could be consolidated)
"""

import json
import gzip
import os
import glob
from collections import defaultdict, Counter
import hashlib
from datetime import datetime
import argparse

def load_events_from_file(filepath):
    """Load events from a gzipped JSON file."""
    try:
        with gzip.open(filepath, 'rt') as f:
            data = json.load(f)
            return data.get('events', []), data.get('batch_id'), data.get('created_at')
    except Exception as e:
        print(f"Error loading {filepath}: {e}")
        return [], None, None

def get_event_hash(event):
    """Create a hash of the event content (excluding ID and timestamp)."""
    # Create a copy of the event without ID and timestamp for comparison
    event_copy = event.copy()
    event_copy.pop('id', None)
    event_copy.pop('timestamp', None)
    
    # Sort the dictionary to ensure consistent hashing
    event_str = json.dumps(event_copy, sort_keys=True)
    return hashlib.md5(event_str.encode()).hexdigest()

def get_similarity_key(event):
    """Create a key for grouping similar events."""
    return (
        event.get('event_type'),
        event.get('source'),
        event.get('hostname'),
        event.get('agent_id'),
        event.get('data', {}).get('System', {}).get('description', '').split(':')[0] if event.get('data', {}).get('System', {}).get('description') else None
    )

def analyze_events(data_dir, max_groups_to_show=10, verbose=False):
    """Analyze all event files for duplicates and redundancies."""
    print(f"Analyzing events in {data_dir}...")
    
    # Dictionaries to track various types of duplicates
    event_ids = {}  # event_id -> (file, event)
    content_hashes = defaultdict(list)  # content_hash -> [(file, event), ...]
    similarity_groups = defaultdict(list)  # similarity_key -> [(file, event), ...]
    
    # Statistics
    total_events = 0
    total_files = 0
    
    # Process all event files
    event_files = glob.glob(os.path.join(data_dir, "events_*.json.gz"))
    
    for filepath in event_files:
        events, batch_id, created_at = load_events_from_file(filepath)
        if not events:
            continue
            
        total_files += 1
        total_events += len(events)
        
        for event in events:
            event_id = event.get('id')
            
            # Check for exact ID duplicates
            if event_id in event_ids:
                print(f"EXACT DUPLICATE ID: {event_id}")
                print(f"  First seen in: {event_ids[event_id][0]}")
                print(f"  Also found in: {filepath}")
                print()
            else:
                event_ids[event_id] = (filepath, event)
            
            # Check for content duplicates
            content_hash = get_event_hash(event)
            content_hashes[content_hash].append((filepath, event))
            
            # Group similar events
            similarity_key = get_similarity_key(event)
            similarity_groups[similarity_key].append((filepath, event))
    
    print(f"Analysis complete!")
    print(f"Total files processed: {total_files}")
    print(f"Total events found: {total_events}")
    print()
    
    # Report content duplicates
    content_duplicates = {k: v for k, v in content_hashes.items() if len(v) > 1}
    print(f"Content duplicates found: {len(content_duplicates)}")
    
    # Limit output to prevent truncation unless verbose mode
    shown_groups = 0
    
    for hash_key, duplicate_events in content_duplicates.items():
        if not verbose and max_groups_to_show and shown_groups >= max_groups_to_show:
            remaining = len(content_duplicates) - shown_groups
            print(f"\n... and {remaining} more duplicate groups (use --verbose or --output to see all)")
            break
            
        print(f"\nContent duplicate group (hash: {hash_key[:8]}...):")
        for filepath, event in duplicate_events:
            print(f"  File: {os.path.basename(filepath)}")
            print(f"  Event ID: {event.get('id')}")
            print(f"  Type: {event.get('event_type')}")
            print(f"  Source: {event.get('source')}")
            print(f"  Timestamp: {event.get('timestamp')}")
        print()
        shown_groups += 1
    
    # Report similarity groups (potential redundancies)
    large_similarity_groups = {k: v for k, v in similarity_groups.items() if len(v) > 10}
    print(f"Large similarity groups (>10 events): {len(large_similarity_groups)}")
    
    for sim_key, similar_events in large_similarity_groups.items():
        print(f"\nSimilarity group: {sim_key}")
        print(f"  Count: {len(similar_events)}")
        
        # Show timestamps to identify potential time-based patterns
        timestamps = [event.get('timestamp') for _, event in similar_events if event.get('timestamp')]
        if timestamps:
            print(f"  First timestamp: {min(timestamps)}")
            print(f"  Last timestamp: {max(timestamps)}")
        else:
            print(f"  No timestamps available")
        
        # Show sample event
        sample_event = similar_events[0][1]
        if sample_event.get('data', {}).get('System', {}).get('description'):
            print(f"  Sample description: {sample_event['data']['System']['description'][:100]}...")
        
        print()
    
    # Summary statistics
    print("="*50)
    print("SUMMARY")
    print("="*50)
    print(f"Total events: {total_events}")
    print(f"Unique content hashes: {len(content_hashes)}")
    print(f"Content duplicate groups: {len(content_duplicates)}")
    print(f"Similarity groups: {len(similarity_groups)}")
    print(f"Large similarity groups (>10): {len(large_similarity_groups)}")
    
    # Calculate potential savings
    duplicate_events = sum(len(events) - 1 for events in content_duplicates.values())
    print(f"Events that could be deduplicated: {duplicate_events}")
    
    redundant_events = sum(len(events) - 1 for events in large_similarity_groups.values())
    print(f"Potentially redundant events: {redundant_events}")
    
    return content_duplicates, large_similarity_groups

def main():
    parser = argparse.ArgumentParser(description='Find duplicate and redundant events in EDR data')
    parser.add_argument('--data-dir', default='data', help='Directory containing event files')
    parser.add_argument('--output', help='Output file for detailed report')
    parser.add_argument('--max-groups', type=int, default=10, help='Maximum duplicate groups to show (default: 10)')
    parser.add_argument('--verbose', '-v', action='store_true', help='Show all duplicate groups')
    
    args = parser.parse_args()
    
    if not os.path.exists(args.data_dir):
        print(f"Error: Directory {args.data_dir} does not exist")
        return 1
    
    try:
        max_groups = args.max_groups if not args.verbose else None
        content_duplicates, similarity_groups = analyze_events(args.data_dir, max_groups, args.verbose)
        
        if args.output:
            print(f"\nSaving detailed report to: {args.output}")
            with open(args.output, 'w') as f:
                json.dump({
                    'content_duplicates': {k: [(filepath, event) for filepath, event in v] 
                                         for k, v in content_duplicates.items()},
                    'similarity_groups': {str(k): [(filepath, event) for filepath, event in v] 
                                        for k, v in similarity_groups.items()}
                }, f, indent=2, default=str)
            print(f"Detailed report saved successfully!")
        
        return 0

    except KeyboardInterrupt:
        print("\nAnalysis interrupted by user")
        return 1
    except Exception as e:
        print(f"\nError during analysis: {str(e)}")
        return 1

if __name__ == "__main__":
    main()

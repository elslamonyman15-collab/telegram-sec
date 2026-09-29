#!/usr/bin/env python3
"""
Test script for Telegram Bot commands
Tests all implemented command handlers
"""

import asyncio
import sys
import os

# Set UTF-8 encoding for Windows console
if sys.platform == 'win32':
    import codecs
    sys.stdout = codecs.getwriter('utf-8')(sys.stdout.buffer, 'strict')
    sys.stderr = codecs.getwriter('utf-8')(sys.stderr.buffer, 'strict')

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from telegram_bot import TelegramBotManager
from unittest.mock import Mock, AsyncMock


class MockUpdate:
    """Mock Telegram Update object"""
    def __init__(self, chat_id=8198840556):
        self.effective_chat = Mock()
        self.effective_chat.id = chat_id
        self.message = Mock()
        self.message.reply_text = AsyncMock()
        self.message.chat_id = chat_id


class MockContext:
    """Mock Telegram Context object"""
    def __init__(self, args=None):
        self.args = args or []


async def test_command(bot_manager, command_name, command_func, chat_id=8198840556, args=None):
    """Test a single command"""
    print(f"\n{'='*60}")
    print(f"Testing /{command_name}")
    print(f"{'='*60}")
    
    update = MockUpdate(chat_id)
    context = MockContext(args)
    
    try:
        await command_func(update, context)
        
        # Check if reply_text was called
        if update.message.reply_text.called:
            calls = update.message.reply_text.call_args_list
            print(f"✅ Command executed successfully")
            print(f"   Response count: {len(calls)}")
            for i, call in enumerate(calls[:3]):  # Show first 3 responses
                msg = call[0][0] if call[0] else ""
                print(f"   Response {i+1}: {msg[:100]}...")
        else:
            print(f"⚠️ No response sent")
            
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()


async def main():
    """Main test function"""
    print("="*60)
    print("Telegram Bot Command Test Suite")
    print("="*60)
    
    # Initialize bot manager
    print("\nInitializing TelegramBotManager...")
    bot_manager = TelegramBotManager()
    
    # Check authorization
    test_chat_id = 8198840556
    if not bot_manager.is_authorized(test_chat_id):
        print(f"❌ Chat ID {test_chat_id} is not authorized")
        return
    print(f"✅ Chat ID {test_chat_id} is authorized")
    
    # Test all commands
    commands_to_test = [
        # Information commands
        ("start", bot_manager.cmd_start),
        ("status", bot_manager.cmd_status),
        ("help", bot_manager.cmd_help),
        
        # Scanning commands
        ("scan_quick", bot_manager.cmd_scan_quick),
        ("scan_network", bot_manager.cmd_scan_network),
        ("scan_process", bot_manager.cmd_scan_process),
        ("scan_registry", bot_manager.cmd_scan_registry),
        ("scan_memory", bot_manager.cmd_scan_memory),
        ("scan", bot_manager.cmd_scan),
        
        # Information commands
        ("last", bot_manager.cmd_last),
        ("last_critical", bot_manager.cmd_last_critical),
        ("summary", bot_manager.cmd_summary),
        ("processes", bot_manager.cmd_processes),
        ("connections", bot_manager.cmd_connections),
        ("users", bot_manager.cmd_users),
        ("tasks", bot_manager.cmd_tasks),
        ("services", bot_manager.cmd_services),
        
        # Control commands
        ("export", bot_manager.cmd_export),
        ("clear", bot_manager.cmd_clear),
        
        # Admin commands
        ("ps", bot_manager.cmd_ps, ["explorer"]),
        ("kill", bot_manager.cmd_kill, ["1234"]),
        ("block_ip", bot_manager.cmd_block_ip, ["1.2.3.4"]),
        ("unblock_ip", bot_manager.cmd_unblock_ip, ["1.2.3.4"]),
    ]
    
    for cmd_data in commands_to_test:
        if len(cmd_data) == 2:
            command_name, command_func = cmd_data
            args = None
        else:
            command_name, command_func, args = cmd_data
        
        await test_command(bot_manager, command_name, command_func, test_chat_id, args)
        await asyncio.sleep(0.5)  # Small delay between tests
    
    print("\n" + "="*60)
    print("Test Suite Complete")
    print("="*60)


if __name__ == "__main__":
    asyncio.run(main())

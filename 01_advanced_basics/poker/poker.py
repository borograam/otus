#!/usr/bin/env python
# -*- coding: utf-8 -*-

# -----------------
# Реализуйте функцию best_hand, которая принимает на вход
# покерную "руку" (hand) из 7ми карт и возвращает лучшую
# (относительно значения, возвращаемого hand_rank)
# "руку" из 5ти карт. У каждой карты есть масть(suit) и
# ранг(rank)
# Масти: трефы(clubs, C), пики(spades, S), червы(hearts, H), бубны(diamonds, D)
# Ранги: 2, 3, 4, 5, 6, 7, 8, 9, 10 (ten, T), валет (jack, J), дама (queen, Q), король (king, K), туз (ace, A)
# Например: AS - туз пик (ace of spades), TH - дестяка черв (ten of hearts), 3C - тройка треф (three of clubs)

# Задание со *
# Реализуйте функцию best_wild_hand, которая принимает на вход
# покерную "руку" (hand) из 7ми карт и возвращает лучшую
# (относительно значения, возвращаемого hand_rank)
# "руку" из 5ти карт. Кроме прочего в данном варианте "рука"
# может включать джокера. Джокеры могут заменить карту любой
# масти и ранга того же цвета, в колоде два джокерва.
# Черный джокер '?B' может быть использован в качестве треф
# или пик любого ранга, красный джокер '?R' - в качестве черв и бубен
# любого ранга.

# Одна функция уже реализована, сигнатуры и описания других даны.
# Вам наверняка пригодится itertools.
# Можно свободно определять свои функции и т.п.
# -----------------

import itertools
from collections import defaultdict

LETTERS = ('T', 'J', 'Q', 'K', 'A')
COLOR_SUIT_MAP = {
    'B': ('C', 'S'),
    'R': ('H', 'D'),
}
RANK_MAP = {letter: i+10 for i, letter in enumerate(LETTERS)}


def hand_rank(hand):
    """Возвращает значение определяющее ранг 'руки'"""
    ranks = card_ranks(hand)
    if straight(ranks) and flush(hand):
        return 8, max(ranks)
    elif kind(4, ranks):
        return 7, kind(4, ranks), kind(1, ranks)
    elif kind(3, ranks) and kind(2, ranks):
        return 6, kind(3, ranks), kind(2, ranks)
    elif flush(hand):
        return 5, *ranks
    elif straight(ranks):
        return 4, max(ranks)
    elif kind(3, ranks):
        return 3, kind(3, ranks), *ranks
    elif two_pair(ranks):
        return 2, *two_pair(ranks), *ranks
    elif kind(2, ranks):
        return 1, kind(2, ranks), *ranks
    else:
        return 0, *ranks


def get_rank_number(card):
    rank = card[0]
    if '2' <= rank <= '9':
        return int(rank)
    return RANK_MAP[rank]  # validate?


def card_ranks(hand):
    """Возвращает список рангов (его числовой эквивалент),
    отсортированный от большего к меньшему"""
    return sorted((get_rank_number(card) for card in hand), reverse=True)


def flush(hand):
    """Возвращает True, если все карты одной масти"""
    return equal(x[1] for x in hand)


def equal(iterable):
    first = None
    for i, item in enumerate(iterable):
        if i == 0:
            first = item
        elif item != first:
            return False
    return True


def straight(ranks):
    """Возвращает True, если отсортированные ранги формируют последовательность 5ти,
    где у 5ти карт ранги идут по порядку (стрит)"""
    return equal(r + i for r, i in zip(ranks, itertools.count()))


def kind(n, ranks):
    """Возвращает первый ранг, который n раз встречается в данной руке.
    Возвращает None, если ничего не найдено"""
    for k, group in itertools.groupby(ranks):
        if len(list(group)) == n:
            return k


def two_pair(ranks):
    """Если есть две пары, то возврщает два соответствующих ранга,
    иначе возвращает None"""
    d = defaultdict(list)
    for k, group in itertools.groupby(ranks):
        d[len(list(group))].append(k)
    if len(d[2]) == 2:
        return d[2][0], d[2][1]


def compare_ranks(rank1, rank2):
    for i1, i2 in zip(rank1, rank2):
        if i2 - i1 != 0:
            return i2 - i1
    return 0


def _best_hand_choice(hands):
    the_best_rank = (0, 0, 0)
    the_best_hand = None
    for cur_hand in hands:
        cur_rank = hand_rank(cur_hand)
        if compare_ranks(the_best_rank, cur_rank) > 0:
            the_best_rank, the_best_hand = cur_rank, cur_hand
    return list(the_best_hand)


def best_hand(hand):
    """Из "руки" в 7 карт возвращает лучшую "руку" в 5 карт """
    return _best_hand_choice(itertools.combinations(hand, 5))


def all_suit_cards(suit):
    for n in itertools.chain(range(2, 10), LETTERS):
        yield f'{n}{suit}'


def replace_joker_generator(hands, joker):
    color = joker[1]
    for hand in hands:
        for suit in COLOR_SUIT_MAP[color]:
            for new_card in all_suit_cards(suit):
                if new_card not in hand:
                    yield tuple(card if card != joker else new_card for card in hand)


def best_wild_hand(hand):
    """best_hand но с джокерами"""
    hands = (hand,)
    for color in COLOR_SUIT_MAP:
        joker = f'?{color}'
        if joker in hand:
            hands = replace_joker_generator(hands, joker)

    # самый тупой и долгий способ - каждую подстановку джокера проводим через best_hand, результаты сводим в лучший.
    # единственный плюс - оно как бы mapreduce и в теории должно легко параллелиться
    if False:
        return _best_hand_choice(best_hand(hand_) for hand_ in hands)

    # высчитаем уникальные перестановки по 5 карт среди всех комбинаций подстановок джокера, чтобы не перебирать
    # одинаковые случаи. Уменьшаем количество рассматриваемых 5-пар на 44% с одним джокером и на 59% с двумя джокерами
    # (не учитывая дополнительный пересчёт с сравнении рангов "победивших" в каждой подстановке, т.е. реальная польза
    # ещё выше). На ситуации без джокеров проигрываем лишь в памяти и затрат времени на конструирование множества
    hands5 = {hand5 for hand7 in hands for hand5 in itertools.combinations(hand7, 5)}
    return _best_hand_choice(hands5)


def test_best_hand():
    print("test_best_hand...")
    assert (sorted(best_hand("6C 7C 8C 9C TC 5C JS".split()))
            == ['6C', '7C', '8C', '9C', 'TC'])
    assert (sorted(best_hand("TD TC TH 7C 7D 8C 8S".split()))
            == ['8C', '8S', 'TC', 'TD', 'TH'])
    assert (sorted(best_hand("JD TC TH 7C 7D 7S 7H".split()))
            == ['7C', '7D', '7H', '7S', 'JD'])
    print('OK')


def test_best_wild_hand():
    print("test_best_wild_hand...")
    assert (sorted(best_wild_hand("6C 7C 8C 9C TC 5C ?B".split()))
            == ['7C', '8C', '9C', 'JC', 'TC'])
    assert (sorted(best_wild_hand("TD TC 5H 5C 7C ?R ?B".split()))
            == ['7C', 'TC', 'TD', 'TH', 'TS'])
    assert (sorted(best_wild_hand("JD TC TH 7C 7D 7S 7H".split()))
            == ['7C', '7D', '7H', '7S', 'JD'])
    print('OK')


if __name__ == '__main__':
    test_best_hand()
    test_best_wild_hand()

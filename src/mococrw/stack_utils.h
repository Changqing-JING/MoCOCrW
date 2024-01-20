/*
 * #%L
 * %%
 * Copyright (C) 2018 BMW Car IT GmbH
 * %%
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * #L%
 */
#pragma once

namespace mococrw
{
namespace utility
{
/**
 * Prior to use, please ensure that the ownership of elements inside the container are not
 * transfered to the stack. If care is not taken and the stack destroys its elements, double frees
 * can erroneously occur. Therefore, please check ownership relation before using this function.
 */
template <class StackSmartPtrType, class ContainerType>
auto buildStackFromContainer(const ContainerType &cnt)
{
    auto stack = mococrw::openssl::createManagedOpenSSLObject<StackSmartPtrType>();
    for (const auto &elem : cnt) {
        mococrw::openssl::addObjectToStack(stack.get(), elem.internal());
    }
    return stack;
}

/**
 * Prior to use, please ensure that the stack truly owns the elements it contains.
 * This function will shift the ownership of the elements inside the stack to the owner of the
 * container. At the end, the stack will be left with no owned elements. If care is not taken and
 * the the owner of the container destroys its elements along with OpenSSL internally destroying the
 * same memory, double frees can erroneously occur. Therefore, please check ownership relation
 * before using this function.
 */
template <class StackType, class StackSmartPtrType, class ContainerType, class ObjectSmartPtrType>
auto buildContainerFromStackAndMoveOwnership(StackSmartPtrType &stack)
{
    ContainerType container;
    auto size = mococrw::openssl::sizeOfStack(stack.get());

    for (auto i = 0; i < size; i++) {
        auto elem = mococrw::openssl::shiftFromStack<StackType, ObjectSmartPtrType>(stack.get());
        container.emplace_back(typename ContainerType::value_type(std::move(elem)));
    }

    return container;
}

}  // namespace utility
}  // namespace mococrw
